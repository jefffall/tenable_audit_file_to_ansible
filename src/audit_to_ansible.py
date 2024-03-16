import xmltodict
import json
import re

def file_to_list(file_handle):
    mylist = []
    for item in file_handle:
        if item[0] != "+":
            if item.strip():
                mylist.append(item.strip())
    return mylist
"""
Purge double quotes
"""
def pdq(mystring):
    if len(mystring ) < 1:
        return(mystring)
    if mystring[0] == '"':
        mystring = mystring[1:]
    if mystring[len(mystring)-1] == '"':
        mystring = mystring[:-1]
    return mystring

def gather_denoted_facts(mylist):
    # find all of the form "Noun" :
    myfacts_spaced_quote = []
    for line in mylist:
        if " : " in line and line[0] != "#":
            parts = line.split(":",1)
            char_string = ''.join((x for x in parts[0] if not x.isdigit()))
            char_string = char_string.strip()
            if len(char_string) > 1:
                if char_string not in myfacts_spaced_quote:
                    #clean_string = ''.join(filter(str.isalnum, char_string))
                    clean_string = char_string.replace("\\","")
                    myfacts_spaced_quote.append(clean_string)
                    
    # find all of the form: "Noun:"
    myfacts_appended_quote = []
    for line in mylist:
        myline = line.strip()
        if len(line) < 34:
            if ":" in myline and myline[0] != "#" and myline[0] != "<":
                parts = myline.split(":",1)
                first_word = ''.join((x for x in parts[0] if not x.isdigit()))
                first_word = first_word.strip().lower()
                if len(first_word) > 1:
                    first_word = first_word + ":"
                    if first_word not in myfacts_appended_quote:
                        first_word = first_word.replace("\\","")
                        first_word = first_word.replace("#","")
                        first_word = first_word.strip()
                        
                        myfacts_appended_quote.append(first_word)
                        
    myfacts_spaced_quote.sort(key=len, reverse=True)
    myfacts_appended_quote.sort(key=len, reverse=True)
    
    
    return myfacts_spaced_quote, myfacts_appended_quote
    

        
def parse_audit_list(mylist):
    #custom_item = False
    #item = False
    current_token = "untokenized"
    list2 = []
    
    for line in mylist:
        if len(line) > 34:
            line = line.strip()
            line = line.replace("<","&lt;")
            line = line.replace(">","&gt;")
            line = line.replace("&","&amp;")
            line = line.replace("--","dashdash")
                
        if len(line) > 0:
            
            if line[0] == "#":
                #list2.append("<!-- "+str(line)+" -->")
                list2.append("<?ignore "+str(line)+" ?>")
            elif "<check_type:" in  line:
                parts = line.split(":")
                list2.append("<check_type>")
                myarg = parts[1]
                myarg = myarg[1:]
                myarg = myarg[:-2]
                list2.append("<this_check_type>"+str(myarg).strip()+"</this_check_type>")
            elif "&amp;lt;group_policy:" in  line:
                parts = line.split(":",1)
                list2.append("<group_policy>")
                myarg = parts[1]
                myarg = myarg[1:]
                myarg = myarg[:-2]
                list2.append("<this_check_type>"+str(myarg).strip()+"</this_check_type>")
            elif "<condition type:" in  line:
                list2.append("<condition>")
                parts = line.split(":",1)
                list2.append("<condition_type>"+str(parts[1])[1:][:-2]+"</condition_type>")
            #elif "Impact:" in  line:
                #current_token = "impact"
            elif "<report type:" in  line:
                list2.append("<report>")
                parts = line.split(":",1)
                list2.append("<report_type>"+str(parts[1])[1:][:-2]+"</report_type>")   
            elif "info" in line and " : " in line:
                current_token = "info"
                parts = line.split(":",1)
                list2.append("<info>"+pdq(str(parts[1]).replace('"', '').strip())+"</info>")
            elif "system" in line and " : " in line:
                current_token = "system"
                parts = line.split(":",1)
                list2.append("<system>"+pdq(str(parts[1]).replace('"', '').strip())+"</system>")
            elif "type" in line and " : " in line and not "value_type" in line:
                current_token = "type"
                parts = line.split(":",1)
                list2.append("<type>"+pdq(str(parts[1]).replace('"', '').strip())+"</type>")
            elif "value_type" in line and " : " in line:
                current_token = "value_type"
                parts = line.split(":",1)
                list2.append("<value_type>"+pdq(str(parts[1]).replace('"', '').strip())+"</value_type>")
            elif "service" in line and " : " in line:
                current_token = "service"
                parts = line.split(":",1)
                list2.append("<service>"+pdq(str(parts[1]).replace('"', '').strip())+"</service>")
            elif "levels" in line and " : " in line:
                current_token = "levels"
                parts = line.split(":",1)
                list2.append("<levels>"+pdq(str(parts[1]).replace('"', '').strip())+"</levels>")
            elif "status" in line and " : " in line:
                current_token = "status"
                parts = line.split(":",1)
                list2.append("<status>"+pdq(str(parts[1]).replace('"', '').strip())+"</status>")
            elif "description" in line and " : " in line:
                current_token = "description"
                parts = line.split(":",1)
                list2.append("<description>"+pdq(str(parts[1]).replace('"', '').strip())+"</description>")
            elif "file" in line and " : " in line:
                current_token = "file"
                parts = line.split(":",1)
                list2.append("<file>"+pdq(str(parts[1]).replace('"', '').strip())+"</file>")
            elif "type" in line and " : " in line:
                current_token = "type"
                parts = line.split(":",1)
                list2.append("<regex>"+pdq(str(parts[1]).replace('"', '').strip())+"</regex>")
            elif "expect" in line and " : " in line:
                current_token = "expect"
                parts = line.split(":",1)
                list2.append("<expect>"+pdq(str(parts[1]).replace('"', '').strip())+"</expect>")
                #list2.append("<expect>expect goes here</expect>")
            elif "cmd" in line and " : " in line:
                current_token = "cmd"
                parts = line.split(":",1)
                list2.append("<cmd>"+pdq(str(parts[1]).replace('"', '').strip())+"</cmd>")
                #list2.append("<cmd>cmd goes here</cmd>")
            elif "reference" in line and " : " in line:
                current_token = "reference"
                parts = line.split(":",1)
                list2.append("<reference>"+pdq(str(parts[1]).replace('"', '').strip())+"</reference>")
            elif "reg_option" in line and " : " in line:
                current_token = "reg_option"
                parts = line.split(":",1)
                list2.append("<reg_option>"+pdq(str(parts[1]).replace('"', '').strip())+"</reg_option>")
                #list2.append("<reference>my ref here</reference>")
            elif "solution" in line and " : " in line:
                current_token = "solution"
                parts = line.split(":",1)
                list2.append("<solution>"+pdq(str(parts[1]).replace('"', '').strip())+"</solution>")
            elif "description" in line and " : " in line:
                current_token = "description"
                parts = line.split(":",1)
                list2.append("<description>"+pdq(str(parts[1]).replace('"', '').strip())+"</description>")
            elif "see_also" in line and " : " in line:
                print("see_also")
                current_token = "see_also"
                parts = line.split(":",1)
                list2.append("<see_also>"+pdq(str(parts[1]).replace('"', '').strip())+"</see_also>")
            elif "dont_echo_command" in line and " : " in line:
                current_token = 'dont_echo_command'
                parts = line.split(":",1)
                list2.append("<dont_echo_command>"+pdq(str(parts[1]).replace('"', '').strip())+"</dont_echo_command>")
            elif "Rationale:" in line:
                current_token = 'rationale'
                parts = line.split(":",1)
                if len(parts[1]) > 0:
                    list2.append("<rationale>"+pdq(str(parts[1]).replace('"', '').strip())+"</rationale>") 
            elif "Note:" in line or "NOTE:" in line:
                current_token = 'note'
                parts = line.split(":",1)
                if len(parts[1]) > 0:
                    list2.append("<note>"+pdq(str(parts[1]).replace('"', '').strip())+"</note>")
            elif "Notes:" in line or "NOTES:" in line:
                current_token = 'notes'
                parts = line.split(":",1)
                if len(parts[1]) > 0:
                    list2.append("<notes>"+pdq(str(parts[1]).replace('"', '').strip())+"</notes>")
            elif "name" in line and " : " in line:
                current_token = 'name'
                parts = line.split(":",1)
                list2.append("<name>"+pdq(str(parts[1]).replace('"', '').strip())+"</name>")
            elif "mask" in line and " : " in line:
                current_token = 'mask'
                parts = line.split(":",1)
                list2.append("<mask>"+pdq(str(parts[1]).replace('"', '').strip())+"</mask>")
            elif "owner" in line and " : " in line:
                current_token = 'owner'
                parts = line.split(":",1)
                list2.append("<owner>"+pdq(str(parts[1]).replace('"', '').strip())+"</owner>")
            elif "string_required" in line and " : " in line:
                current_token = 'string_required'
                parts = line.split(":",1)
                list2.append("<string_required>"+pdq(str(parts[1]).replace('"', '').strip())+"</string_required>")
            elif "severity" in line and " : " in line:
                current_token = 'severity'
                parts = line.split(":",1)
                list2.append("<severity>"+pdq(str(parts[1]).replace('"', '').strip())+"</severity>")
            elif "rpm" in line and " : " in line:
                current_token = 'rpm'
                parts = line.split(":",1)
                list2.append("<rpm>"+pdq(str(parts[1]).replace('"', '').strip())+"</rpm>")
            elif "operator" in line and " : " in line:
                current_token = 'operator'
                parts = line.split(":",1)
                list2.append("<operator>"+pdq(str(parts[1]).replace('"', '').strip())+"</operator>")
            elif "required" in line and " : " in line:
                current_token = 'required'
                parts = line.split(":",1)
                list2.append("<required>"+pdq(str(parts[1]).replace('"', '').strip())+"</required>")
            elif "group" in line and " : " in line:
                current_token = 'group'
                parts = line.split(":",1)
                list2.append("<group>"+pdq(str(parts[1]).replace('"', '').strip())+"</group>")
            elif "lockout_policy" in line and " : " in line:
                current_token = 'lockout_policy'
                parts = line.split(":",1)
                list2.append("<lockout_policy>"+pdq(str(parts[1]).replace('"', '').strip())+"</lockout_policy>")
            elif "right_type" in line and " : " in line:
                current_token = 'right_type'
                parts = line.split(":",1)
                list2.append("<right_type>"+pdq(str(parts[1]).replace('"', '').strip())+"</right_type>")
            elif "value_data" in line and " : " in line:
                current_token = 'value_data'
                parts = line.split(":",1)
                list2.append("<value_data>"+pdq(str(parts[1]).replace('"', '').strip())+"</value_data>")
            elif "password_policy" in line and " : " in line:
                current_token = 'password_policy'
                parts = line.split(":",1)
                list2.append("<password_policy>"+pdq(str(parts[1]).replace('"', '').strip())+"</password_policy>")
            elif "reg_key" in line and " : " in line:
                current_token = 'reg_key'
                parts = line.split(":",1)
                list2.append("<reg_key>"+pdq(str(parts[1]).replace('"', '').strip())+"</reg_key>")
            elif "reg_item" in line and " : " in line:
                current_token = 'reg_item'
                parts = line.split(":",1)
                list2.append("<reg_item>"+pdq(str(parts[1]).replace('"', '').strip())+"</reg_item>")
            elif "regex" in line and " : " in line:
                current_token = 'regex'
                parts = line.split(":",1)
                list2.append("<regex>"+pdq(str(parts[1]).replace('"', '').strip())+"</regex>")
            elif "Impact:" in line:
                print ("Impact found")
                current_token = 'impact'
                parts = line.split(":",1)
                if len(parts[1]) > 0:
                    list2.append("<impact>"+pdq(str(parts[1]).replace('"', '').strip())+"</impact")
            elif "Example:" in line or "example" in line[:8].lower():
                #print ("line", line[:7].lower())
                current_token = 'example'
                try:
                    parts = line.split(":",1)
                except:
                    line.split("example")
                if len(parts[1]) > 0:
                    list2.append("<example>"+pdq(str(parts[1]).replace('"', '').strip())+"</example>")
            elif "Default Value:" in line:
                current_token = 'default_value'
                parts = line.split(":",1)
                if len(parts[1]) > 0:
                    list2.append("<default_value>"+pdq(str(parts[1]).replace('"', '').strip())+"</default_value>")
            elif "The recommended state for this setting is:" in line:
                current_token = 'recommended_state'
                parts = line.split(":",1)
                if len(parts[1]) > 0:
                    list2.append("<recommended_state>"+pdq(str(parts[1]).replace('"', '').strip())+"</recommended_state>")
            elif "run the following command" in line.lower() or "run the command" in line.lower():
                line_lower = line.lower()
                current_token = 'run_command'
                try:
                    parts = line_lower.split("run the following command")
                except:
                    parts = line_lower.split("run the command")
                    #print ("run the command", line)
                try:
                    if len(parts[1]) > 0:
                        command = parts[1]
                except:
                    command = "command line(s) are below"
                list2.append("<run_command>"+pdq(str(command).replace('"', '').strip())+"</run_command>")
            elif "add the following line:" in line.lower():
                line_lower = line.lower()
                current_token = 'add_line'
                parts = line_lower.split("add the following line:")
                if len(parts[1]) > 0:
                    list2.append("<add_line>"+pdq(str(parts[1]).replace('"', '').strip())+"</add_line>")
            elif "add or edit " in line.lower():
                line_lower = line.lower()
                current_token = 'add_or_edit'
                parts = line_lower.split("add or edit ")
                if len(parts[1]) > 0:
                    list2.append("<add_or_edit>"+pdq(str(parts[1]).replace('"', '').strip())+"</add_or_edit>")
            elif "additional information" in line.lower():
                line_lower = line.lower()
                current_token = 'additional_information'
                parts = line_lower.split("additional information:")
                try:
                    if len(parts[1]) > 0:
                        list2.append("<additional_information>"+pdq(str(parts[1]).replace('"', '').strip())+"</additional_information>")
                except:
                    pass
            elif "set the following parameters" in line.lower():
                line_lower = line.lower()
                current_token = 'set_parameters'
                parts = line_lower.split("set the following parameters")
                if len(parts[1]) > 0:
                    list2.append("<set_parameters>"+pdq(str(parts[1]).replace('"', '').strip())+"</set_parameters>")
            else:
                if len(line) < 16 and "<" in line and ">" in line:
                    list2.append(pdq(line.strip()))
                else:
                    if len(line) > 0:
                        #if ":" in line:
                            #print (line)
                        line = line.replace("<","&lt;")
                        line = line.replace(">","&gt;")
                        line = line.replace("&","&amp;")
                        line = line.replace("--","dashdash")
                        line = line.replace('"', '')
                        list2.append("<"+current_token+">"+pdq(line.strip())+"</"+current_token+">")
                """
                if "&amp;lt;custom_item&amp;gt;" in line:
                    list2.append("<custom_item>")
                elif  "&amp;lt;/custom_item&amp;gt;" in line:
                    list2.append("</custom_item>")
                elif  "&amp;lt;/custom_item&amp;gt;" in line:
                    list2.append("</custom_item>")
                """
               
    return list2

def parse_audit_list2(mylist,myfacts_spaced_quote, myfacts_appended_quote):
    #custom_item = False
    #item = False
    current_token = "untokenized"
    list2 = []
    
    for line in mylist:
        if len(line) > 34:
            line = line.strip()
            line = line.replace("<","&lt;")
            line = line.replace(">","&gt;")
            line = line.replace("&","&amp;")
            line = line.replace("--","dashdash")
                
        if len(line) > 0:
            
            if line[0] == "#":
                #list2.append("<!-- "+str(line)+" -->")
                list2.append("<?ignore "+str(line)+" ?>")
            elif "<check_type:" in  line:
                parts = line.split(":")
                list2.append("<check_type>")
                myarg = parts[1]
                myarg = myarg[1:]
                myarg = myarg[:-2]
                list2.append("<this_check_type>"+str(myarg).strip()+"</this_check_type>")
            elif "&amp;lt;group_policy:" in  line:
                parts = line.split(":",1)
                list2.append("<group_policy>")
                myarg = parts[1]
                myarg = myarg[1:]
                myarg = myarg[:-2]
                list2.append("<this_check_type>"+str(myarg).strip()+"</this_check_type>")
            elif "<condition type:" in  line:
                list2.append("<condition>")
                parts = line.split(":",1)
                list2.append("<condition_type>"+str(parts[1])[1:][:-2]+"</condition_type>")
            elif "Impact:" in  line:
                current_token = "impact"
            elif "<report type:" in  line:
                list2.append("<report>")
                parts = line.split(":",1)
                list2.append("<report_type>"+str(parts[1])[1:][:-2]+"</report_type>")
            else:
                my_scan = False
                for fact in myfacts_spaced_quote:
                    if fact in line.lower() and " : " in line:
                        current_token = fact
                        parts = line.split(":",1)
                        my_scan = True
                        if len(parts[1]) > 1:
                            list2.append("<"+str(fact.lower())+">"+pdq(str(parts[1]).replace('"', '').strip())+"</"+str(fact.lower())+">")
                            break
                        
                if my_scan == False:
                    for fact in myfacts_appended_quote:
                        if fact in line.lower():
                            current_token = fact[:-1]
                            current_token = current_token.replace(" ","_")
                            parts = line.split(":",1)
                            clean_tag = re.sub('[^A-Za-z0-9]+', '', parts[0])
                            clean_tag = clean_tag.replace(" ","_")
                            my_scan = True
                            if len(clean_tag) > 0 and len(parts[1]) > 0:
                                list2.append("<"+str(clean_tag.lower())+">"+pdq(str(parts[1]).replace('"', '').strip())+"</"+str(clean_tag.lower())+">")
                                break
                                
                if my_scan == False:
                    if len(line) > 33: 
                        line = line.replace("<","&lt;")
                        line = line.replace(">","&gt;")
                        line = line.replace("&","&amp;")
                        line = line.replace("--","dashdash")
                        line = line.replace('"', '')
                        #print (pdq(line.strip()))
                        list2.append("<"+current_token+">"+pdq(line.strip())+"</"+current_token+">")
                    else:
                        if len(line) > 0 and line[0] == "<":
                            list2.append(pdq(line.strip()))
                            
                        
    return list2
        

def xml_list_to_string(mylist):      
    big_str = ""
    big_str = big_str + "<root>\n"
    for line in mylist:
        big_str = big_str + line.strip() + "\n"
    big_str = big_str + "</root>\n"
    return big_str


    
def debug_print_no_line_numbers(mylist):
    line_count = 1
    #print (line_count, "<root>")
    print ("<root>")
    for line in mylist:
        line_count = line_count + 1
        print (line)
        #print(line_count, line) 
        #print(line_count,"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789")
        if line_count > 90000:
            break
    #print (line_count, "</root>\n")
    print ("</root>\n")
    
def debug_print_with_line_numbers(mylist):
    line_count = 1
    print (line_count, "<root>")
    for line in mylist:
        line_count = line_count + 1
        print(line_count, line) 
        #print(line_count,"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789")
        if line_count > 90000:
            break
    print (line_count, "</root>\n")
   
    
    
def string_to_dict(big_string):
    mydict = xmltodict.parse(big_string)      
    return mydict 


def string_to_json(big_string):
    mydict = xmltodict.parse(big_string)      
    # Serializing json   
    json_object = json.dumps(mydict, indent = 4)  
    return json_object 

def scrub_json(json_obj):
    json_obj.replace("\n","",100000)
    return json_obj

audit_file_fd = open("Windows_2019_L1.txt", "r")
#audit_file_fd = open("CIS_SUSE_Linux_Enterprise_Server_12_v2.1.0_L1.audit.txt", "r")
#audit_file_fd = open("CIS_Red_Hat_EL7_v3.1.1_Server_L1.audit.txt","r")

raw_audit_list = file_to_list(audit_file_fd)
myfacts_spaced_quote, myfacts_appended_quote = gather_denoted_facts(raw_audit_list)
#xml_list = parse_audit_list(raw_audit_list)
xml_list = parse_audit_list2(raw_audit_list, myfacts_spaced_quote, myfacts_appended_quote)

print (myfacts_spaced_quote)
print (myfacts_appended_quote)

debug_print_with_line_numbers(xml_list)
xml_audit_string = xml_list_to_string(xml_list).strip()
#print (xml_audit_string)
mydict = string_to_dict(xml_audit_string)
audit_json = string_to_json(xml_audit_string)
good_json = scrub_json(audit_json)
print(good_json)
#print (mydict)

"""
for json_data in mydict['root']['check_type']:
    for attribute, value in json_data.iteritems():
        print (attribute, value) # example usage
"""
#for line in mydict['root']['check_type']['if']['condition']['custom_item']:
    #print (line)
"""    
jsonObject = json.loads(good_json)


def print_dict(dictionary):
    dictionary_array = [dictionary]
    for sub_dictionary in dictionary_array:
        print (type(sub_dictionary))
        if type(sub_dictionary) is dict:
            for key, value in sub_dictionary.items():
                print("key=", key)
                print("value", value)
                if type(value) is dict:
                    dictionary_array.append(value)




d2 = dict(mydict)
print (type(d2))

print_dict(d2)
"""
    

    


