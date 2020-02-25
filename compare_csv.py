import re
import sys

try:
    import csv
    import traceback
except ImportError as e:
    raise Exception("Failed to import module", e)

summary_file = act = exp = ""
line_number = 0
csv_dict_header_linerange_mappings = {}
csv_report_header = header_holder = expected_headers = actual_headers = []
validation_flag = True


def validate_csv_report(expectedoutput, actualoutput, summary):
    """
    This method compares the CSV report and reports the differences to summary file.
    :param expectedoutput: Expected CSV Report
    :param actualoutput: Actual CSV Report
    :param summary: Summary file to which differences will be spooled
    """
    global summary_file, act, exp
    global line_number
    global validation_flag

    summary_file = open(summary, 'w')
    act = open(actualoutput)
    actualcsv = csv.reader(act)
    exp = open(expectedoutput)
    expectedcsv = csv.reader(exp)
    _map_csv_reportheaders_with_records(expectedoutput)
    csv.field_size_limit(sys.maxsize)
    actual_rows = list(actualcsv)
    expected_rows = list(expectedcsv)
    goaheadflag = _write_report_summary(expectedoutput, actualoutput, summary_file)
    if goaheadflag:
        proceedflag = _compare_column_headers(expectedoutput, actualoutput, summary_file)
        if proceedflag:
            summary_file.write(f"Report Data Comparison:\n")
            for line in range(len(actual_rows)):
                _tokencounter = 0
                try:
                    if actual_rows[line] != expected_rows[line]:
                        for act, exp in zip(actual_rows[line], expected_rows[line]):
                            if act != exp:
                                columnname = _get_column_name(line + 1, _tokencounter)
                                deviation_header = "<Column_Data_Deviation_" + columnname.replace(" ", "_") + ">|"
                                summary_file.write(
                                    f"{deviation_header} Line: {line + 1} | Column: {columnname} | Expected [ {exp} ]: Actual [ {act} ]\n")
                            validation_flag = False
                            _tokencounter += 1
                except IndexError:
                    summary_file.write(traceback.print_exc())
                    _close_files()
                    validation_flag = False
            if validation_flag:
                summary_file.write(f"\tNo differences in report data\n")
                _close_files()
            return validation_flag
        else:
            _close_files()
            return False
    else:
        _close_files()
        return False


def _close_files():
    global summary_file, act, exp
    act.close()
    exp.close()
    summary_file.close()


def _compare_column_headers(expectedoutput, actualoutput, summaryfile):
    """
    This method compares the headers from CSV report
    :param expectedoutput: 
    :param actualoutput: 
    """
    global expected_headers, actual_headers, validation_flag
    expected_headers = _get_column_headers(expectedoutput)
    actual_headers = _get_column_headers(actualoutput)
    summaryfile.write(f"Column header Comparison:")
    _mismatchflag = False
    mismatchedHeaders = 0

    for index in range(len(expected_headers)):
        if expected_headers[index] != actual_headers[index]:
            summaryfile.write(
                f"\n<Column_Header_Deviation>| Columns that are not matching from Expected output and Actual output")
            summaryfile.write(f"\n\tExpected : {expected_headers[index]})")
            summaryfile.write(f"\n\tActual : {actual_headers[index]})\n")
            validation_flag = False
            mismatchedHeaders += 1
    if mismatchedHeaders != 0:
        summaryfile.write(
            f"\n\tDifferences in column headers were observed for {mismatchedHeaders} rows\n\n\tTermminating...")
        summaryfile.write('\n' + '*' * 100 + '\n')
        summaryfile.close()
        return False
    else:
        summaryfile.write(f"\n\tNo differences in column headers were observed\n")
        summaryfile.write('\n' + '*' * 100 + '\n')
        return True


def _write_report_summary(expectedoutput, actualoutput, summaryfile):
    """
    This method dumps additional details of expected and actual report
    :param expectedoutput:
    :param actualoutput:
    :param summaryfile:
    :return:
    """
    _expected_rec_count = _getRecordCount(expectedoutput)
    _actual_rec_count = _getRecordCount(actualoutput)
    summaryfile.write('*' * 100 + '\n' + 'VM Report comparison Summary :\n')
    summaryfile.write('*' * 100 + '\n')
    summaryfile.write(f"Record count comparison:\n")
    summaryfile.write(f"Expected Report:")
    summaryfile.write(f"\n\tPath : [ {expectedoutput} ])")
    summaryfile.write(f"\n\tRecord count: {_expected_rec_count}\n")
    summaryfile.write(f"\nActual Report:")
    summaryfile.write(f"\n\tPath : [ {actualoutput} ])")
    summaryfile.write(f"\n\tRecord count: {_actual_rec_count}\n")
    if _expected_rec_count != _actual_rec_count:
        summaryfile.write(f"\n\t<Record_Count_Deviation>| Record count is not matching\n\n\tTermminating...")
        summaryfile.write('\n' + '*' * 100 + '\n')
        summaryfile.close()
        return False
    else:
        summaryfile.write('*' * 100 + '\n')
        return True


def _get_column_name(headerline_number, coulmnindex):
    """
    This method returns the Column name of CSV record data value based on column index .
    :param headerline_number: Line number of record
    :param coulmnindex: Index of column
    :return: String
    """
    global csv_dict_header_linerange_mappings
    return csv_dict_header_linerange_mappings[headerline_number][coulmnindex]


def _getRecordCount(report):
    """
    This method returns count of records from CSV report.
    :param vmreport: CSV report
    :return: boolean
    """
    return sum(1 for row in csv.reader(open(report)))


def _map_csv_reportheaders_with_records(expectedreport):
    global line_number
    global header_holder, expected_headers, actual_headers
    global csv_dict_header_linerange_mappings

    line_number = 1
    headerflag = True
    descriptionflag = True
    rowflag = True

    with open(expectedreport, newline='') as csvfile:
        reportreader = csv.reader(csvfile)
        for row in reportreader:
            if row:
                line_number += 1
                if descriptionflag:
                    csv_dict_header_linerange_mappings[line_number - 1] = row

                if headerflag and not descriptionflag:
                    if row[0].startswith('by'):
                        continue
                    else:
                        header_holder = row
                        headerflag = False
                        rowflag = True

                if rowflag and not descriptionflag:
                    csv_dict_header_linerange_mappings[line_number - 1] = header_holder
                continue
            else:
                line_number += 1
                headerflag = True
                descriptionflag = False
                rowflag = False


def _get_column_headers(output):
    """
    This method returns list of headers present in output file
    :param output: List
    :return: headers[]
    """
    headers = []
    headerflag = True
    descriptionFlag = True

    with open(output, newline='') as csvfile:
        reportreader = csv.reader(csvfile)
        for row in reportreader:
            if row:
                if headerflag and not descriptionFlag:
                    if row[0].startswith('by'):
                        continue
                    else:
                        headers.append(row)
                        headerflag = False
                continue
            else:
                headerflag = True
                # Report Metadata
                descriptionFlag = False
    csvfile.close()
    return headers


def validate_xml_report(param, param1, param2):
    """
    Placeholder for XML Report
    :param param:
    :param param1:
    :param param2:
    :return:
    """
    pass


def is_deviation_present_for_data(validation_summary, search_this):
    """
    This method returns True, if given column name is marked as a deviation in Report Comparison summary file
    :param validation_summary: Path of Summary file
    :param search_this: Column name to be searched
    :return: True, if column name found, else False
    """
    summary = open(validation_summary, "r")
    for line in summary:
        if re.search(search_this, line):
            print(f"Found {search_this} in {summary_file} \n Line: {line}")
            return True
        else:
            return False


def validate_vm_report(report_type, expected_report, actual_report, validation_summary):
    if report_type == 'csv':
        return validate_csv_report(expected_report, actual_report, validation_summary)
    elif report_type == 'pdf':
        return validate_xml_report(expected_report, actual_report, validation_summary)


validate_vm_report("csv", "C:\\temp\\q.csv", "C:\\temp\\v.csv", "C:\\temp\\summary.txt")
