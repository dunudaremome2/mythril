from mythril.analysis.swc_data import SWC_TO_TITLE

class ExtractInfo():
    
    def __init__(self) -> None:
        pass
    
    def check_vuln(self, issues: list) -> list[dict]:
        list_of_swc_sorted_list = self.sort_issues_by_swc(issues) 
        # [[{'title': 'a', 'swc-id': '101'}, {'title': 'c', 'swc-id': '101'}, {'title': 'd', 'swc-id': '101'}], 
        #  [{'title': 'b', 'swc-id': '104'}, {'title': 'e', 'swc-id': '104'}]]
        result = []
        for same_swc_list in list_of_swc_sorted_list:
            id = same_swc_list[0]["swc-id"]
            match id:
                case "101": 
                    d = self.extract_integer_of_uf(same_swc_list)
                    # self.write_to_file("mythril_integer", d)
                case "104": 
                    d = self.common_extract(same_swc_list)
                    # self.write_to_file("mythril_unchecked", d)
                case "107": 
                    d = self.extract_reentrancy(same_swc_list)
                    # self.write_to_file("mythril_reentrancy", d)
                case "115": 
                    d = self.common_extract(same_swc_list)
                    # self.write_to_file("mythril_tx_origin", d)
                case "116": 
                    d = self.common_extract(same_swc_list)
                    # self.write_to_file("mythril_timestamp", d)
            if d is not None:
                result.extend(d)
        return result
                
          
    def write_to_file(self, output_filename: str, dictttttt: list[dict]):
        f = open(rf"C:/Users/elysi/OneDrive/Desktop/output/{output_filename}.txt", "a")
        for indiv in dictttttt:
            for key, value in indiv.items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
        f.close()
         
    def sort_issues_by_swc(self, issues: list[dict]) -> list[list[dict]]:
        list_of_list_of_issues = []
        swc_ids = []
        for issue in issues:
            swc_id = issue["swc-id"]
            if swc_id not in swc_ids:
                swc_ids.append(swc_id)
                list_of_list_of_issues.append([issue])
            else:
                swc_id_index = swc_ids.index(swc_id)
                list_of_list_of_issues[swc_id_index].append(issue)
        return list_of_list_of_issues
                    
    def find_func_lines(self, func_name, file):
        '''find the start and end lines of the function name'''
        check = []
        result = []
        func_name = func_name.split("(")[0]
        f = open(file, "r")
        for (num, line) in enumerate(f, 1):
            if func_name in line:
                check.append("{")
                start_line = num
                result.append(start_line)
                end_line = None
                nums = start_line
                while end_line is None:
                    for line in f.readlines():
                        nums += 1
                        if "{" in line:
                            check.append("{")
                        if "}" in line:
                            check.pop()
                        if len(check) == 0:
                            end_line = nums
                            result.append(end_line)
                            break  
        return result
                    
    def remove_duplicates_reentrancy(self, issues: list[dict], pc_address: list) -> list[dict]:
        '''find same dictionaries and only take one dictionary 
        but append all the different program counter addresses into that one dictionary'''
        location_index = None
        list_of_tuples = []
        temp_dic = {}
        final = []
        
        for (index, dic) in enumerate(issues):
            list_of_tuples.append((index, dic))
            
        for i in range(len(list_of_tuples)):
            if i == len(list_of_tuples)-1:
                break
            current = list_of_tuples[i]
            next = list_of_tuples[i+1]
            if current[1] == next[1]:
                location_index = current[0]
                temp_dic = current[1].copy()
                temp_dic['pc_addresses'] = f"{pc_address[location_index]}, {pc_address[location_index + 1]}"
                item_to_be_removed = [current, next]
                for item in item_to_be_removed:
                    list_of_tuples.remove(item)
                list_of_tuples.append((location_index, temp_dic.copy()))
                list_of_tuples.sort()
                temp_dic.clear()
        for item in list_of_tuples:
            final.append(item[1])
        return final
    
    def remove_duplicates_arithmetic(self, issues: list[dict]) -> list[dict]:
        '''find same function names and merge all the code and line into one dictionary'''
        unique_issues = []
        codesNlines = []
        unique_functions = []

        for issue_index, issue in enumerate(issues):
            code = issue.pop("code")
            line = issue.pop("lineno")
            if issue['function'] not in unique_functions:
                unique_functions.append(issue['function'])
                unique_issues.append(issue)
                codesNlines.append([(code, line)])
            else:
                index_of_duplicate = unique_functions.index(issue['function'])
                codesNlines[index_of_duplicate].append((code, line))

        for issue_index in range(len(unique_issues)):
            for codeNline_index, codeNline in enumerate(codesNlines[issue_index]):
                unique_issues[issue_index]["code" + str(codeNline_index or "")] = codeNline[0]
                unique_issues[issue_index]["lineno" + str(codeNline_index or "")] = codeNline[1]
            
        return unique_issues
    
    def extract_reentrancy(self, issues: list[dict]) -> list[dict]:
        result = []
        var = {}
        pc_address = []
        for issue in issues:
            
            severity_level = issue["severity"]
            swcid = issue["swc-id"]
            title = SWC_TO_TITLE[swcid]
            reason = issue["title"].lower().capitalize()
            
            function_name = issue["function"]
            function_line = self.find_func_lines(issue["function"], issue["filename"])
            
            node_name = issue["code"]
            node_line = issue["lineno"]
            
            additional = "Violation in code"
            
            pc_address.append(issue["address"])
            
            var["severity_level"] = severity_level
            var["swcid"] = swcid
            var["title"] = title
            var["reason"] = reason
            var["function_name"] = function_name
            var["function_line"] = function_line
            var["additional"] = additional
            if reason.startswith("External"):
                var["excall"] = "External call(s)"
            elif reason.startswith("State"):
                var["var_written"] = "State variables written after the call(s)"
            var["node_name"] = node_name
            var["node_line"] = node_line
            
            result.append(var.copy())
            
            var.clear()
                        
        final = self.remove_duplicates_reentrancy(result, pc_address)
        # print(final)
        return final
       
    def common_extract(self, issues: list[dict]) -> list[dict]:
        result = []
        var = {}
        for issue in issues:
            
            severity_level = issue["severity"]
            swcid = issue["swc-id"]
            title = SWC_TO_TITLE[swcid]
            reason = issue["title"].lower().capitalize()
            
            function_name = issue["function"]
            function_line = self.find_func_lines(issue["function"], issue["filename"])
            
            node_name = issue["code"]
            node_line = issue["lineno"]
            
            additional = "Violation in code"
            
            var["severity_level"] = severity_level
            var["swcid"] = swcid
            var["title"] = title
            var["reason"] = reason
            var["function_name"] = function_name
            var["function_line"] = function_line
            var["additional"] = additional
            var["node_name"] = node_name
            var["node_line"] = node_line
            
            result.append(var.copy())
            
            var.clear()
            
        return result
    
    def extract_integer_of_uf(self, issues: list[dict]) -> list[dict]:
        result = []
        var = {}
        issues = self.remove_duplicates_arithmetic(issues)
        for issue in issues:
            
            var = issue.copy()
            # dict_keys(['title', 'swc-id', 'contract', 'description', 'function', 'severity', 'address', 'tx_sequence', 
            # 'min_gas_used', 'max_gas_used', 'sourceMap', 'filename', 'lineno', 'code'])
            
            var["severity_level"] = var.pop("severity")
            var["swcid"] = var.pop("swc-id")
            reason = issue["title"].lower().capitalize()
            var["title"] = SWC_TO_TITLE[var["swcid"]]
            var["reason"] = reason
            var["function_name"] = var.pop("function")
            var["function_line"] = self.find_func_lines(var["function_name"], var["filename"])
            var["additional"] = "Violation in code"
            
            # change code* to node_name* and lineno* to node_line*
            wanted_keys = list(issue.keys())[12:]
            for key in wanted_keys:
                if key.startswith("code"):
                    num = key[4:]
                    name = "node_name" + str(num)
                    var[name] = var.pop(key)
                elif key.startswith("lineno"):
                    num = key[6:]
                    line = "node_line" + str(num)
                    var[line] = var.pop(key)
            
            var.pop("contract"), var.pop("description"), var.pop("address"), var.pop("tx_sequence"), var.pop("min_gas_used"), var.pop("max_gas_used"), var.pop("sourceMap"), var.pop("filename")
            
            result.append(var.copy())
            
            var.clear()
                        
        # print(result)
        return result
