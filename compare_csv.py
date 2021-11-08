import csv
import itertools
import os
import re
import traceback
from collections import OrderedDict
from collections import namedtuple
from functools import reduce
from operator import add

SectionMetaData = namedtuple('SectionMetaData', ['section_start', 'header', 'rpt_section'])
ErrorMsg = namedtuple('ErrorMsg', ['line_no', 'error_msg'])  # , 'column_name', 'expected_value', 'actual_value'
success_msg = 'No deviations found in report data'
failure_msg = 'Deviations observed in report data'


def _getRecordCount(vmreport):
    """
    This method returns count of records from CSV report.
    :param vmreport: CSV report
    :return: boolean
    """
    return sum(1 for row in csv.reader(open(vmreport)))


def read_report_sections_in_dict(fileName):
    rpt_section_dict = OrderedDict()

    line_no = 1

    with open(fileName, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file)
        section_meta_data = None
        for row in csv_reader:
            if row is None or not row:
                section_meta_data = None
            else:
                if not is_row_skippable(row):
                    if section_meta_data is None:
                        section_meta_data = create_section_metadata(line_no, row)
                        # sorted_header = sorted(row)
                        sorted_header = row
                        header_str_key = '|'.join(str(column).strip() for column in sorted_header)
                        rpt_section_dict[header_str_key] = section_meta_data

                    if is_row_col_val_conv_req(line_no, row):
                        row = convert_row_to_col_val(section_meta_data.header, row)
                        section_meta_data.rpt_section.append(row)

            line_no += 1

    return rpt_section_dict


def is_row_skippable(row):
    Columns_to_be_skipped = ['by Status', 'by Severity']
    if row[0] in Columns_to_be_skipped:
        return True
    return False


def get_section_key(section_header):
    col_list_1 = ['IP', 'Network', 'Total Vulnerabilities', 'Security Risk']
    col_list_2 = ['Status', 'Confirmed', 'Potential', 'Total']
    col_list_3 = ['Severity', 'Confirmed', 'Potential', 'Information Gathered', 'Total']
    col_list_4 = ['IP', 'DNS', 'NetBIOS', 'OS', 'IP Status']
    col_list_5 = ['Asset Groups', 'IPs', 'Active Hosts']
    col_list_6 = ['Total Vulnerabilities']
    col_list_7 = ["Launch Date", "Active Hosts", "Total Hosts", "Type", "Status", "Reference", "Scanner Appliance", "Duration", "Scan Title"]


    # check if row contains all elements of col_list_2 using all()
    res_1 = all(elem in section_header for elem in col_list_1)
    res_2 = all(elem in section_header for elem in col_list_2)
    res_3 = all(elem in section_header for elem in col_list_3)
    res_4 = all(elem in section_header for elem in col_list_4)
    res_5 = all(elem in section_header for elem in col_list_5)
    res_6 = all(elem in section_header for elem in col_list_6)
    res_7 = all(elem in section_header for elem in col_list_7)

    if res_1 & res_2 & res_3 & res_4 & res_5 & res_6 & res_7:
        raise Exception("bitwise operation (res_1 & res_2 & res_3 & res_4 & res_5 & res_6 & res_7) must not be true")

    if res_1:
        return lambda row: str(row["IP"] + "|" + row["Network"]).replace(" ", "")
    elif res_2:
        return lambda row: str(row["Status"]).replace(" ", "")
    elif res_3:
        return lambda row: str(row["Severity"]).replace(" ", "")
    elif res_4:
        return lambda row: str(row["IP"] +  "|" + row["DNS"] + "|" + row["NetBIOS"] + "|" + row[
            "QID"] + "|" + row["Type"] + "|" + row["Port"] + "|" + row["Protocol"] + "|" + row["FQDN"] + "|" + str(row[
                                   "Instance"])).replace(" ", "")
    elif res_5:
        return lambda row: str(row["Asset Groups"] + "|" + row["IPs"] + "|" + row["Active Hosts"]).replace(" ", "")
    elif res_6:
        return lambda row: str(row["Total Vulnerabilities"]).replace(" ", "")
    elif res_7:
        return lambda row: str(row["Launch Date"]).replace(" ", "")
    else:
        return None


def compare_rpt_section(expected_section_meta_data, actual_section_meta_data):
    expected_section_meta_data = SectionMetaData(*expected_section_meta_data)
    actual_section_meta_data = SectionMetaData(*actual_section_meta_data)

    section_header = expected_section_meta_data.header

    rpt_row_list = expected_section_meta_data.rpt_section
    sec_start_line_no = expected_section_meta_data.section_start

    section_key_lambda = get_section_key(section_header)

    if section_key_lambda is None:
        print("")
    else:
        for row in range(1, len(expected_section_meta_data.rpt_section)):
            key_str = section_key_lambda(row)


def conv_section_rows_to_dict(section_row_list, section_key_lambda):
    csv_row_per_key = OrderedDict()
    for row in range(1, len(section_row_list)):
        key_str = section_key_lambda(row)
        csv_row_per_key[key_str] = row
    return csv_row_per_key


def is_row_col_val_conv_req(line_no, row):
    excl_header_str_list = ['No vulnerabilities match your filters for these hosts',
                            'No results available for these hosts']
    if line_no <= 3:
        return False
    else:
        for str in excl_header_str_list:
            if any(str in col_val for col_val in row):
                return False
    return True


def create_section_metadata(line_no, header):
    rpt_section = []
    section_start = line_no
    section_meta_data = SectionMetaData(section_start, header, rpt_section)
    return section_meta_data


def compare_no_of_rpt_sections(expected_dict, actual_dict):
    err_msg_list = []

    no_of_expected_sections = len(expected_dict)
    no_of_actual_sections = len(actual_dict)

    if no_of_actual_sections != no_of_actual_sections:
        error_msg = ErrorMsg(None, "Deviation in no. of report sections | Expected :" | {
            no_of_expected_sections} | ": Actual :" | {no_of_actual_sections})

        err_msg_list.append(error_msg)
        for key, value in expected_dict.items():
            if key not in actual_dict:
                exp_header = value.header
                eror_msg = ErrorMsg(None, "Section with header: [" | {exp_header} | "] not present in Actual Report")
                err_msg_list.append(eror_msg)
    return err_msg_list


def convert_row_to_col_val(fieldnames, row):
    d = OrderedDict(zip(fieldnames, row))
    lf = len(fieldnames)
    lr = len(row)
    if lf < lr:
        d[None] = row[lf:]
    elif lf > lr:
        for key in fieldnames[lr:]:
            d[key] = None
    return d


def compare_report_header(map_1_headers, map_2_headers):
    columns_not_matching_per_key = []
    go_ahead_flag = True
    columns_not_matching_per_key.append(f"Comparing column headers:")
    if len(map_1_headers) != len(map_2_headers):
        msg = f"Column_Header_Deviation | Expected Column count: [{len(map_1_headers)}] | Actual Column count: [{len(map_2_headers)}]"
        columns_not_matching_per_key.append(msg)
        go_ahead_flag = False
    for expected_column in map_1_headers:
        if expected_column not in map_2_headers:
            msg = f"Column_Header_Deviation | Expected Column: [{expected_column}] not found Actual Column list: [{map_2_headers}]"
            columns_not_matching_per_key.append(msg)
            go_ahead_flag = False
    for actual_column in map_2_headers:
        if actual_column not in map_1_headers:
            msg = f"Column_Header_Deviation | Actual Column: [{actual_column}] not found Expected Column list: [{map_1_headers}]"
            columns_not_matching_per_key.append(msg)
            go_ahead_flag = False

    if map_1_headers == map_2_headers:
        go_ahead_flag = True
        columns_not_matching_per_key.append(f"No deviation found in column headers")
    return go_ahead_flag, columns_not_matching_per_key


def _get_req_data_from_record(data_row):
    display_columns_for_missing_data = ['IP', 'Network', 'DNS', 'NetBIOS', 'OS', 'QID']
    msg = ' '
    separator = ' | '
    for key, value in data_row.items():
        if key in display_columns_for_missing_data:
            msg += key + ":" + data_row.get(key) + separator
    return msg


def _get_list_data_as_string(data_list, enable_numbering=True):
    result = ''
    item_no = 1
    if enable_numbering:
        for data in data_list:
            if len(data) != 0:
                result += '\n[' + str(item_no) + '] ' + str(data) + '\n'
                item_no += 1
    else:
        for data in data_list:
            if len(data) != 0:
                if isinstance(data, list):
                    for item in data:
                        result += '\n' + str(item) + '\n'
                else:
                    result += '\n' + str(data) + '\n'
                item_no += 1
    return result


def compare_odict_keys(exp, act):
    diff = []
    compare_headers = False
    skip_key = False
    if compare_headers:
        diff = list(set(exp) - set(act))
    else:
        for key in exp.keys():
            if not skip_key:
                skip_key = True
                continue
            else:
                if key not in act.keys():
                    diff.append(key)
    return diff


def compare_report_sections(map_1, map_2):
    section_error_messages = []
    go_ahead_flag = True
    msg = "Section comparison summary:"
    section_error_messages.append(msg)
    msg = f"Number of sections in Expected report: {len(map_1)}"
    section_error_messages.append(msg)
    msg = f"Number of sections in Actual report: {len(map_2)}"
    section_error_messages.append(msg)

    present_in_expected_missing_in_actual = compare_odict_keys(map_1, map_2)
    present_in_actual_missing_in_expected = compare_odict_keys(map_2, map_1)
    print(_get_list_data_as_string(present_in_expected_missing_in_actual))
    if not len(present_in_expected_missing_in_actual) == 0:
        msg = f"Report_Section_Deviation | Following sections are present in Expected report and absent in Actual report: {_get_list_data_as_string(present_in_expected_missing_in_actual)}"
        section_error_messages.append(msg)
        go_ahead_flag = False
    if not len(present_in_actual_missing_in_expected) == 0:
        msg = f"Report_Section_Deviation | Following sections are present in Actual report and absent in Expected report: {_get_list_data_as_string(present_in_actual_missing_in_expected)}"
        section_error_messages.append(msg)
        go_ahead_flag = False
    return go_ahead_flag, section_error_messages


def remove_space_CRLF(string):
    return re.sub('\r?\n', '', string).strip().replace(" ", "")


def compare_report_data_dicts(exp, act, explinenumber, actlinenumber):
    data_error_message = []
    skip_columns = ['Date Range']
    data_mismatch_flag = True
    for key, value in exp.items():
        if key not in skip_columns:
            if key in act.keys():
                if remove_space_CRLF(value) != remove_space_CRLF(act.get(key)):
                    deviation_header = "Column_Data_Deviation_" + key.replace(" ", "_")
                    msg = f"{deviation_header} | Line in Expected report: {explinenumber} ; Line in Actual report: {actlinenumber} | Column: {key} | Expected: [{value}] Actual: [{act.get(key)}]"
                    data_error_message.append(msg)
                    data_mismatch_flag = False
            else:
                deviation_header = "Column_Data_Deviation_" + key.replace(" ", "_")
                msg = f"{deviation_header} | Line in Expected report: {explinenumber} ; Line in Actual report: {actlinenumber} | Column: {key} is presemt in Expected report, absent in Actual report"
                data_error_message.append(msg)
                data_mismatch_flag = False
    return data_mismatch_flag, data_error_message


def get_data_for_sort_order_validation(lst_odict, header):
    result_lst = []
    result_odict = OrderedDict()
    try:
        header_row_key = get_section_key(header)
        for row in lst_odict:
            row_key = header_row_key(row)
            result_lst.append(row_key)
            result_odict[row_key] = row
    except Exception as e:
        print("Exception occured while validating the reports")
        print(e)
        print(row)
        print(traceback.format_exc())
    return result_lst, result_odict


def find_missing_records(exp, act):
    missing_records = []
    for key, val in exp.items():
        if key not in act.keys():
            missing_records.append(val)
    return missing_records


def compare_report_data(odict_exp, odict_act, exp_section_start, act_section_start):
    data_error_messages = []
    data_mismatch_flags = []
    present_in_exp_absent_in_act = find_missing_records(odict_exp, odict_act)
    present_in_act_absent_in_exp = find_missing_records(odict_act, odict_exp)
    if len(present_in_exp_absent_in_act) != 0:
        present_in_exp_absent_in_act_message = _get_list_data_as_string(present_in_exp_absent_in_act)
        data_error_messages.append(
            f"Records present in Expected report but absent in Actual report:{present_in_exp_absent_in_act_message}")
    if len(present_in_act_absent_in_exp) != 0:
        present_in_act_absent_in_exp_message = _get_list_data_as_string(present_in_act_absent_in_exp)
        data_error_messages.append(
            f"Records present in Actual report but absent in Expected report:{present_in_act_absent_in_exp_message}")
    data_error_messages.append(f"Comparison summary for Report records:")
    for exp_row_key, exp_row_val in odict_exp.items():
        if exp_row_key in odict_act.keys():
            data_mismatch_flag, data_error_message = compare_report_data_dicts(exp_row_val, odict_act.get(exp_row_key),
                                                                               list(odict_exp).index(
                                                                                   exp_row_key) + exp_section_start,
                                                                               list(odict_act).index(
                                                                                   exp_row_key) + act_section_start)
            data_error_messages.append(data_error_message)
            data_mismatch_flags.append(data_mismatch_flag)

    return data_mismatch_flags, data_error_messages


def check_sort_order(lst_exp, lst_act):
    if set(lst_exp) != set(lst_act):
        return [False], ["Sort order in current section of Expected and Actual report is NOT MATCHING"]
    else:
        return [True], ["Sort order in current section of Expected and Actual report is MATCHING"]


def compare_report_data_attributes(expected, actual, exp_headers, act_headers, exp_section_start, act_section_start,
                                   section_title):
    data_error_messages = []
    data_mismatch_flags = []
    if len(expected) != len(actual):
        msg = f"Record_Count_Deviation | Section Title: [ {section_title} ] | Expected Record count: [{len(expected)}] | Actual Record count: [{len(actual)}]"
        data_error_messages.append(msg)
        data_mismatch_flags.append(False)
    lst_exp, odict_exp = get_data_for_sort_order_validation(expected, exp_headers)
    lst_act, odict_act = get_data_for_sort_order_validation(actual, act_headers)
    data_mismatch_flag, data_error_message = compare_report_data(odict_exp, odict_act, exp_section_start,
                                                                 act_section_start)
    data_mismatch_flags.append(data_mismatch_flag)
    data_error_messages.append(data_error_message)

    data_mismatch_flag, data_error_message = check_sort_order(lst_exp, lst_act)
    data_mismatch_flags.append(data_mismatch_flag)
    data_error_messages.append(data_error_message)

    return data_mismatch_flags, data_error_messages


def compare_reports(map_1, map_2):
    master_comparison_flag_list = []
    error_messages = []
    # Compare report sections fisrt
    section_comparison_flag, error_message = compare_report_sections(map_1, map_2)
    error_messages.append(error_message)
    master_comparison_flag_list.append(section_comparison_flag)

    # Compare Headers and Data
    for map_1_header_str, map_1_section_meta_data in map_1.items():
        # Check if key from Actual dict is present in Expected dict
        if map_1_header_str in map_2.keys():
            map_2_section_meta_data = map_2.get(map_1_header_str)

            # Extract the Column headers and Report data from both the dicts
            map_1_headers = map_1_section_meta_data.header
            map_2_headers = map_2_section_meta_data.header
            map_1_rpt_section = map_1_section_meta_data.rpt_section
            map_2_rpt_section = map_2_section_meta_data.rpt_section

            msg = ["*" * 100]
            msg += [f"Data comparison started for section:\n[{map_1_header_str}]"]
            error_messages.append(msg)

            # Compare column header and get the differences in a list
            column_compare_result, error_message = compare_report_header(map_1_headers, map_2_headers)
            error_messages.append(error_message)
            master_comparison_flag_list.append(column_compare_result)

            # Compare report data from section
            data_compare_result, error_message = compare_report_data_attributes(map_1_rpt_section, map_2_rpt_section,
                                                                                map_1_headers, map_2_headers,
                                                                                map_1_section_meta_data.section_start,
                                                                                map_2_section_meta_data.section_start,
                                                                                map_1_header_str)
            error_messages.append(error_message)
            master_comparison_flag_list.append(data_compare_result)
            msg = [f"Data comparison Finished for section\n"]
            msg += ["*" * 100]
            error_messages.append(msg)

    return master_comparison_flag_list, error_messages


def compare_dict(map_1, map_2, map_1_name, map_2_name):
    keys_not_found_list = []
    columns_not_matching_per_key = []
    for map_1_header_str, map_1_section_meta_data in map_1.items():
        # Check if key from Actual dict is present in Expected dict
        if map_1_header_str in map_2.keys():
            map_2_section_meta_data = map_2.get(map_1_header_str)

            # Extract the Column headers and Report data from both the dicts
            headers = map_1_section_meta_data.header
            map_1_rpt_section = map_1_section_meta_data.rpt_section
            map_2_rpt_section = map_2_section_meta_data.rpt_section

            for col_name in headers:
                map_1_cell_val = str(map_1_rpt_section[col_name])
                map_2_cell_val = str(map_2_rpt_section[col_name])

                if map_1_cell_val != map_2_cell_val:
                    msg = "Column: " + col_name + "|  Expected Column: [" + map_1_cell_val + "] | Actual Column: [" + map_2_cell_val + "]"
                    columns_not_matching_per_key.append(msg)

        else:
            tmp = "[SectionMismatchERROR] Section: " + map_1_header_str + " present in " + map_1_name + " but absent in " + map_2_name
            keys_not_found_list.append(tmp)

    print("\n\n\n")
    print("Keys present in " + map_1_name + " but not present in " + map_2_name + "::")
    for item in keys_not_found_list:
        print(item)
    print("\n\n\n")

    columns_not_matching_per_key = sorted(columns_not_matching_per_key)

    print("Columns not matching.....\n")
    for item in columns_not_matching_per_key:
        print(item)


def filter_summary(datalist):
    # Removes empty lists
    return [chunk for chunk in datalist if chunk]


def check_false_in_result(lst):
    flat_res = str(lst)
    if 'False' in flat_res:
        return False
    else:
        return True


def write_report_comparison_summary(flag_list, summary_messages, summary):
    global success_msg, failure_msg
    summary_file = open(summary, "w")
    summary_file.write("*" * 100)
    summary_file.write("\nReport Comparison Summary\n")
    summary_file.write("*" * 100)
    summary_file.write(f"\nOverall Comparison status:")
    if check_false_in_result(flag_list):
        summary_file.write(f"\n{success_msg}\n")
        summary_file.write("*" * 100)
    else:
        summary_file.write(f"\n{failure_msg}\n")
        summary_file.write("*" * 100)
    if len(summary_messages) != 0:
        for message in summary_messages:
            if len(message) == 0:
                continue
            else:
                for data in message:
                    if len(data) != 0:
                        if isinstance(data, list):
                            enable_numbering = False
                            summary_file.write(f"{_get_list_data_as_string(data, enable_numbering)}")
                        else:
                            summary_file.write(f"\n{str(data)}\n")
    summary_file.write("*" * 100)
    summary_file.close()


def assert_comparison(summary):
    global success_msg, failure_msg
    with open(summary, 'r') as read_obj:
        for line in read_obj:
            if success_msg in line:
                return True
    return False


def is_deviation_present_for_data(validation_summary, search_this):
    """
    This method returns True, if given column name is marked as a deviation in Report Comparison summary file
    :param validation_summary: Path of Summary file
    :param search_this: Column name to be searched
    :return: True, if column name found, else False
    """
    col_headers_str = 'Column_Header_Deviation'
    report_absent_str = 'Report_files_not_present'

    print(f"Checking deviation for column {search_this} in {validation_summary}")
    if os.path.getsize(validation_summary) == 0:
        print('Summary file is empty')
        return False, 'Summary file is empty'
    if os.path.isfile(validation_summary):
        with open(validation_summary, "r") as f:
            data = f.readlines()
        f.close()
        _validation_flag = True
        _summary_line = 'Not Found'
        for line in range(len(data)):
            if col_headers_str in data[line] or report_absent_str in data[line]:
                _summary_line = f"Either {col_headers_str} , or {report_absent_str} present in Summary\nWon't check existance of {search_this} in Summary"
                _validation_flag = False
                break
            if search_this in data[line]:
                _summary_line = data[line]
                _validation_flag = False
                break
            else:
                continue
    else:
        print("File does not exist")
    return _validation_flag, _summary_line


def validate_vmcsv_report(expected, actual, summary):
    if os.path.exists(expected) and os.path.exists(actual):
        expected_dict = read_report_sections_in_dict(expected)
        actual_dict = read_report_sections_in_dict(actual)
        # compare_dict(expected_dict, actual_dict, "expected_map", "actual_map")
        flag_list, summary_messages = compare_reports(expected_dict, actual_dict)
    else:
        flag_list = [False]
        summary_messages = [
            ['[ERROR: Report_files_not_present] Expected or Actual file is not present at given location']]

    write_report_comparison_summary(flag_list, summary_messages, summary)
    return assert_comparison(summary)


def validate_vm_report(expected_report, actual_report, validation_summary):
    try:
        return validate_vmcsv_report(expected_report, actual_report, validation_summary)
    except Exception as e:
        print("Exception occured while validating the reports")
        print(e)
        print(traceback.format_exc())
        return False


print(validate_vm_report("C:/temp/q.csv", "C:/temp/v.csv", "C:/temp/summary_new.txt"))
