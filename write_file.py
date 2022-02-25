from androguard.misc import AnalyzeAPK
import os

def WRITE_FEATURES_TO_FILE(dataset_path,apk_name_without_extension,api_call_dictionary,ordered_features):
    apk_file = open(dataset_path + apk_name_without_extension + '.txt', 'w')
    try:
        idx = -1
        apk_file.write("API-CALLS\n")
        for call_class in api_call_dictionary["api_call_class"]:
            idx = idx + 1
            count = 0
            for i in (api_call_dictionary["list_of_count_of_uniqe_methods"][idx]):
                count = count + i
            count_of_uniqe_methods = len(api_call_dictionary["list_of_uniqe_methods"][idx])
            apk_file.write(
                "calling -- " + call_class + " : " + str(count) + "  (" + str(count_of_uniqe_methods) + ")" + "\n\n")
            for j in range(len(api_call_dictionary["list_of_uniqe_methods"][idx])):
                class_method = api_call_dictionary["list_of_uniqe_methods"][idx][j]
                cnt = api_call_dictionary["list_of_count_of_uniqe_methods"][idx][j]
                apk_file.write("calling -- " + call_class + " -- " + class_method + "   : " + str(cnt) + "\n")
            apk_file.write("-------------------------------------------------------------------------\n")
        # print local ordering for an apk
        apk_file.write("---------------------------------------------------------------------------------------------SIRALAMA-------------------------------------------------------------------------\n")
        count_of_uniqe_api_call = len(ordered_features[0]["api_call"])
        apk_file.write(apk_name_without_extension + " has " + str(count_of_uniqe_api_call) + " different api call\n")
        for i in range(count_of_uniqe_api_call):
            apk_file.write(ordered_features[0]["api_call"][i] + " : " + str(ordered_features[0]["count"][i]) + "\n")
        apk_file.write("-------------------------------------------------------------------------\n")

        count_of_uniqe_permission = len(ordered_features[1]["permission"])
        apk_file.write(apk_name_without_extension + " has " + str(count_of_uniqe_permission) + " different permission\n")
        for i in range(count_of_uniqe_permission):
            apk_file.write(ordered_features[1]["permission"][i] + " : " + str(ordered_features[1]["count"][i]) + "\n")
        apk_file.write("-------------------------------------------------------------------------\n")

        count_of_uniqe_action = len(ordered_features[2]["action"])
        apk_file.write(apk_name_without_extension + " has " + str(count_of_uniqe_action) + " different action\n")
        for i in range(count_of_uniqe_action):
            apk_file.write(ordered_features[2]["action"][i] + " : " + str(ordered_features[2]["count"][i]) + "\n")
        apk_file.write("-------------------------------------------------------------------------\n")

        count_of_uniqe_category = len(ordered_features[3]["category"])
        apk_file.write(apk_name_without_extension + " has " + str(count_of_uniqe_category) + " different category\n")
        for i in range(count_of_uniqe_category):
            apk_file.write(ordered_features[3]["category"][i] + " : " + str(ordered_features[3]["count"][i]) + "\n")
        apk_file.write("-------------------------------------------------------------------------\n")

        count_of_uniqe_data = len(ordered_features[4]["data"])
        apk_file.write(apk_name_without_extension + " has " + str(count_of_uniqe_data) + " different data\n")
        for i in range(count_of_uniqe_data):
            apk_file.write(ordered_features[4]["data"][i] + " : " + str(ordered_features[4]["count"][i]) + "\n")
        apk_file.write("-------------------------------------------------------------------------\n")

        count_of_uniqe_meta_data = len(ordered_features[5]["meta_data"])
        apk_file.write(apk_name_without_extension + " has " + str(count_of_uniqe_meta_data) + " different meta data\n")
        for i in range(count_of_uniqe_meta_data):
            apk_file.write(ordered_features[5]["meta_data"][i] + " : " + str(ordered_features[5]["count"][i]) + "\n")
        apk_file.write("-------------------------------------------------------------------------\n")

        apk_file.close()
    except:
        print("Error on " + apk_name_without_extension + "(Broken Manifest File), passing.")
        apk_file.close()
        return -1

def print_local_rank(global_feature_data):
    path_list = ["P:\\Proje Kaynaklar\\Veriseti\\SMS\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Adware\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Banking\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Riskware\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Benign\\"]
    path_names = ["SMS","Adware","Banking","Riskware","Benign"]
    ftr_names = ["API-CALL","PERMISSION","ACTION","CATEGORY","DATA","META-DATA"]
    enum_path_list = enumerate(path_list)

    for count,path in enum_path_list:
        print("Printing " + path_names[count] + " file.")
        ranked_file = open(path + path_names[count] + "_ranked.txt", "w")
        ftr_list = global_feature_data[count]
        for index in range(len(ftr_list)):
            ranked_file.write(ftr_names[index] + "\n")
            ranked_file.write(path_names[count] + " class has " + str(len(ftr_list[index]["feature"])) + " different " + ftr_names[index] + "\n")
            for i in range(len(ftr_list[index]["feature"])):
                ranked_file.write(ftr_list[index]["feature"][i] + " : " + str(ftr_list[index]["count"][i]) + "\n")
            ranked_file.write("-------------------------------------------------------------------------\n")
        ranked_file.close()

def print_global_rank(ranked_dataset_features):
    print("printing global rank")
    path = "P:\\Proje Kaynaklar\\Veriseti\\"
    file = open(path + "ranked_dataset_features.txt","w")
    ftr_names = ["API-CALL", "PERMISSION", "ACTION", "CATEGORY", "DATA", "META-DATA"]
    for count,feature in enumerate(ftr_names):
        class_ranked = ranked_dataset_features[count]
        a = ftr_names[count]
        p = class_ranked["feature"]
        file.write(a + "\n")
        file.write("Dataset has " + str(len(p)) + " different " + a + "\n")
        for i in range(len(p)):
            file.write(p[i] + " : " + str(class_ranked["count"][i]) + "\n")
        file.write("-------------------------------------------------------------------------\n")
    file.close()

def WRITE_APK_CALLS(apk):
    file_name, file_extension = os.path.splitext(apk)
    file = open(file_name + '_calls.txt', 'w')

    app, list_of_dex, dx = AnalyzeAPK(apk)
    for method in dx.get_methods():
        file.write("inside Method {} ".format(method.name) + ':' + '\n')
        for _, call, _ in method.get_xref_to():
            file.write("    calling -> {} -- {}".format(call.class_name, call.name) + '\n')
    file.close()