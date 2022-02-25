# import subprocess
# from write_file import WRITE_APK_CALLS
# import shutil

import xml.etree.ElementTree as ET
from androguard.misc import AnalyzeAPK
import os
from write_file import WRITE_FEATURES_TO_FILE

def extractFeatures():
    # dataset_features en genel listedir. Her sınıfa ait bilgiler bu değişkende tutulur.
    # 5 sınıf olduğu için 5 elemanlı bir listedir
    # 0-SMS, 1-Adware, 2-Banking, 3-Riskware, 4-Benign
    dataset_features = list()
    # apktool aracı ile .apk dosyaları decomiple edilir
    apktool_path = 'P:\\Proje Kaynaklar\\apktool.jar'
    # list_class sırasıyla bütün sınıfların yolunu tutar
    list_class = ["P:\\Proje Kaynaklar\\Veriseti\\SMS\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Adware\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Banking\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Riskware\\",
            "P:\\Proje Kaynaklar\\Veriseti\\Benign\\"]
    count = 0
    # bu for döngüsü her sınıf için bir kere çalışır, toplamda 5 defa döner
    list_class1 = ["P:\\Proje Kaynaklar\\Veriseti\\SMS2\\",
                  "P:\\Proje Kaynaklar\\Veriseti\\Adware2\\"]
    for dataset_path in list_class1:
        class_count = 0
        # class_features bir sınıfa ait bütün apk dosyalarını tutar
        class_features = list()
        apk_files = os.listdir(dataset_path)
        # corrupted_files, bozuk olan apk dosyalarının yazıldığı .txt dosyasıdır
        corrupted = open(dataset_path + "corrupted_files.txt", "w")
        # bu for döngüsü her apk dosyası için çalışır
        # apk_name_with_extension, dosya ismini uzantısıyla birlikte tutar, örneğin apk5.apk
        for apk_name_with_extension in apk_files:
            # ele alınan dosya .apk uzantılı ise bu if içine girer, diğer dosyaları ve klasörleri atlar
            if ".apk" in apk_name_with_extension:
                # apks_ordered_features, bir apk dosyasını temsil eder. İçinde dosyadan çıkartılan her özelliği sıralı olarak tutar.
                # 7 elemanlıdır, label hariç her özellik liste tipindedir ve kendi içerisinde büyükten küçüğe sıralıdır
                # 0-api_call, 1-permission, 2-action, 3-category, 4-data, 5-meta_data, 6-label
                apks_ordered_features = list()
                # apk_full_path, apk dosyasının tam yolunu, dosya ismiyle ve uzantısıyla birlikte tutar, örn C:\Users\usr1\apk1.apk
                apk_full_path = dataset_path + apk_name_with_extension
                # apk dosyasının sınıfı, klasör ismine bakarak öğrenilir
                if "SMS" in dataset_path:
                    label = "SMS"
                elif "Adware" in dataset_path:
                    label = "Adware"
                elif "Banking" in dataset_path:
                    label = "Banking"
                elif "Riskware" in dataset_path:
                    label = "Riskware"
                elif "Benign" in dataset_path:
                    label = "Benign"
                else:
                    label = "unknown"
                # sayı kontrolü

                """
                if label == "SMS" or label == "Adware":
                    if len(class_features) == 3:
                        break
                else:
                    break
                """
                # subprocess.call metodu ile apktool aracı ile bir apk dosyası decompile edilir
                # parametre olarak apktool aracının ve apk dosyasının tam dosya yolunu alır
                # subprocess.call([apktool_path, 'd', apk_full_path], shell=True)
                # apk_name_without_extension, apk dosyasından uzantısının kesilmiş halidir. örn apk5
                apk_name_without_extension = apk_name_with_extension.split(".")[0]
                # manifest_file apk dosyasının decompile sonucu içinden çıkan AndroidManifest.xml dosyasıdır
                try:
                    manifest_file = ET.parse("C:\\Users\\mehmetcan_karabulut\\recompiled_apks\\" + apk_name_without_extension + "\\AndroidManifest.xml").getroot()
                except:
                    print("Error on " + apk_name_without_extension + "(AndroidManifest Not Found), passing.")
                    corrupted.write(apk_name_without_extension + " -> AndroidManifest.xml Not Found\n")
                    continue
                # ----------------------------------- API-CALL ÖZELLİĞİNİN ÇIKARTILMASI ---------------------------------------
                # dct_api_call bir dictionary veriyapısıdır
                # birinci kısmı api_call listesi, ikinci kısmı birincideki api çağrılarının çağırılma sayısını tutan listedir
                # eleman ekleme işlemi paralel olarak yapılır, bir api çağrısı eklendiği zaman çağırılma sayısıda diğer listeye eklenir
                dct_api_call = {"api_call": list(), "count": list()}
                # api_call_dictionary, hesaplamalar için tutulan ara değişkendir
                # birinci kısımda api çağırısının sınıfı, ikinci kısımda bu sınıftan çağırılan metotlar, üçüncü kısımda metotların sayısı tutulur
                api_call_dictionary = {"api_call_class": list(),
                                       "list_of_uniqe_methods": list(),
                                       "list_of_count_of_uniqe_methods": list()}
                try:
                    _, _, dx = AnalyzeAPK(apk_full_path)
                except:
                    print("Invalid Instruction for getting api-call")
                    corrupted.write(apk_name_without_extension + " -> Invalid Instruction\n")
                    continue
                api_call_class_name_set = set()
                for method in dx.get_methods():
                    for _, api_call, _ in method.get_xref_to():
                        api_call_class_name_set.add(api_call.class_name)
                api_call_class_name_list = list(api_call_class_name_set)
                idx = -1
                for api_call_class_name in api_call_class_name_list:
                    api_call_dictionary["api_call_class"].append(api_call_class_name)
                    api_call_dictionary["list_of_uniqe_methods"].append(list())
                    api_call_dictionary["list_of_count_of_uniqe_methods"].append(list())
                    idx = idx + 1
                    for method in dx.get_methods():
                        for _, api_call, _ in method.get_xref_to():
                            if api_call_class_name == api_call.class_name:
                                class_method = api_call.name
                                try:
                                    index = api_call_dictionary["list_of_uniqe_methods"][idx].index(class_method)
                                    api_call_dictionary["list_of_count_of_uniqe_methods"][idx][index] = \
                                    api_call_dictionary["list_of_count_of_uniqe_methods"][idx][index] + 1
                                except:
                                    api_call_dictionary["list_of_uniqe_methods"][idx].append(class_method)
                                    api_call_dictionary["list_of_count_of_uniqe_methods"][idx].append(1)
                # local ordering
                for call_class in api_call_dictionary["api_call_class"]:
                    index = api_call_dictionary["api_call_class"].index(call_class)
                    for k in range(len(api_call_dictionary["list_of_uniqe_methods"][index])):
                        mthd = api_call_dictionary["list_of_uniqe_methods"][index][k]
                        full_api_call = call_class + "/" + mthd
                        cnt = api_call_dictionary["list_of_count_of_uniqe_methods"][index][k]
                        try:
                            idx = dct_api_call["api_call"].index(full_api_call)
                            dct_api_call["count"][idx] = dct_api_call["count"][idx] + 1
                        except:
                            dct_api_call["api_call"].append(full_api_call)
                            dct_api_call["count"].append(cnt)
                try:
                    l1, l2 = (list(t) for t in zip(*sorted(zip(dct_api_call["count"], dct_api_call["api_call"]))))
                    dct_api_call["api_call"] = l2[::-1]
                    dct_api_call["count"] = l1[::-1]
                except:
                    ...
                apks_ordered_features.append(dct_api_call)
                # permission
                # uses-permissions tagı ile çıkarılır
                dct_permission = {"permission": list(), "count": list()}
                permissions = manifest_file.findall("uses-permission")
                permission_list = []
                for permission in permissions:
                    for attribute in permission.attrib:
                        permission_list.append(permission.attrib[attribute])
                # sıralama
                for perm in permission_list:
                    try:
                        index = dct_permission["permission"].index(perm)
                        dct_permission["count"][index] = dct_permission["count"][index] + 1
                    except:
                        dct_permission["permission"].append(perm)
                        dct_permission["count"].append(1)
                try:
                    l1, l2 = (list(t) for t in zip(*sorted(zip(dct_permission["count"], dct_permission["permission"]))))
                    dct_permission["permission"] = l2[::-1]
                    dct_permission["count"] = l1[::-1]
                except:
                    ...
                apks_ordered_features.append(dct_permission)
                # action
                # application/activity/intent-filter/action
                # application/service/intent-filter/action
                # application/receiver/intent-filter/action
                # tagları ile çıkarılır
                dct_action = {"action": list(), "count": list()}
                actions1 = manifest_file.findall("application/activity/intent-filter/action")
                actions2 = manifest_file.findall("application/service/intent-filter/action")
                actions3 = manifest_file.findall("application/receiver/intent-filter/action")
                action_list = []
                for action in actions1:
                    for attribute in action.attrib:
                        action_list.append(action.attrib[attribute])
                for action in actions2:
                    for attribute in action.attrib:
                        action_list.append(action.attrib[attribute])
                for action in actions3:
                    for attribute in action.attrib:
                        action_list.append(action.attrib[attribute])

                for action in action_list:
                    try:
                        index = dct_action["action"].index(action)
                        dct_action["count"][index] = dct_action["count"][index] + 1
                    except:
                        dct_action["action"].append(action)
                        dct_action["count"].append(1)
                try:
                    l1, l2 = (list(t) for t in zip(*sorted(zip(dct_action["count"], dct_action["action"]))))
                    dct_action["action"] = l2[::-1]
                    dct_action["count"] = l1[::-1]
                except:
                    ...
                apks_ordered_features.append(dct_action)
                # category
                # application/activity/intent-list/category
                dct_category = {"category": list(), "count": list()}
                categories = manifest_file.findall("application/activity/intent-filter/category")
                category_list = []
                for category in categories:
                    for attribute in category.attrib:
                        category_list.append(category.attrib[attribute])
                for category in category_list:
                    try:
                        index = dct_category["category"].index(category)
                        dct_category["count"][index] = dct_category["count"][index] + 1
                    except:
                        dct_category["category"].append(category)
                        dct_category["count"].append(1)
                try:
                    l1, l2 = (list(t) for t in zip(*sorted(zip(dct_category["count"], dct_category["category"]))))
                    dct_category["category"] = l2[::-1]
                    dct_category["count"] = l1[::-1]
                except:
                    ...
                apks_ordered_features.append(dct_category)
                # data
                # application/activity/intent-filter/data
                # application/service/intent-filter/data
                # application/receiver/intent-filter/data
                dct_data = {"data": list(), "count": list()}
                datas1 = manifest_file.findall("application/activity/intent-filter/data")
                datas2 = manifest_file.findall("application/service/intent-filter/data")
                datas3 = manifest_file.findall("application/receiver/intent-filter/data")
                data_list = []
                for data in datas1:
                    for attribute in data.attrib:
                        data_list.append(data.attrib[attribute])
                for data in datas2:
                    for attribute in data.attrib:
                        data_list.append(data.attrib[attribute])
                for data in datas3:
                    for attribute in data.attrib:
                        data_list.append(data.attrib[attribute])
                for data in data_list:
                    try:
                        index = dct_data["data"].index(data)
                        dct_data["count"][index] = dct_data["count"][index] + 1
                    except:
                        dct_data["data"].append(data)
                        dct_data["count"].append(1)
                try:
                    l1, l2 = (list(t) for t in zip(*sorted(zip(dct_data["count"], dct_data["data"]))))
                    dct_data["data"] = l2[::-1]
                    dct_data["count"] = l1[::-1]
                except:
                    ...
                apks_ordered_features.append(dct_data)
                # meta-data
                # application/meta-data
                # application/service/meta-data
                # application/receiver/meta-data
                dct_meta_data = {"meta_data": list(), "count": list()}
                metas1 = manifest_file.findall("application/meta-data")
                metas2 = manifest_file.findall("application/service/meta-data")
                metas3 = manifest_file.findall("application/receiver/meta-data")
                meta_data_list = []
                for meta in metas1:
                    for attribute in meta.attrib:
                        meta_data_list.append(meta.attrib[attribute])
                for meta in metas2:
                    for attribute in meta.attrib:
                        meta_data_list.append(meta.attrib[attribute])
                for meta in metas3:
                    for attribute in meta.attrib:
                        meta_data_list.append(meta.attrib[attribute])
                for meta_data in meta_data_list:
                    try:
                        index = dct_meta_data["meta_data"].index(meta_data)
                        dct_meta_data["count"][index] = dct_meta_data["count"][index] + 1
                    except:
                        dct_meta_data["meta_data"].append(meta_data)
                        dct_meta_data["count"].append(1)
                try:
                    l1, l2 = (list(t) for t in zip(*sorted(zip(dct_meta_data["count"], dct_meta_data["meta_data"]))))
                    dct_meta_data["meta_data"] = l2[::-1]
                    dct_meta_data["count"] = l1[::-1]
                except:
                    # hiç özellik bulunamazsa buraya düşer
                    ...
                apks_ordered_features.append(dct_meta_data)
                apks_ordered_features.append(label)
                apks_ordered_features.append(apk_name_without_extension)
                # --------------------------------------------- PRINT -------------------------------------------
                if WRITE_FEATURES_TO_FILE(dataset_path, apk_name_without_extension, api_call_dictionary,
                                          apks_ordered_features) == -1:
                    corrupted.write(apk_name_without_extension + " -> Broken AndroidManifest File\n")
                    continue
                # WRITE_APK_CALLS(apk_full_path)
                class_features.append(apks_ordered_features)
                count = count + 1
                class_count = class_count + 1
                print(apk_name_with_extension + " : " + label + "       / " + str(count) + " (" + label + " " + str(class_count) + ")")
            else:
                continue
        corrupted.close()
        dataset_features.append(class_features)
        # shutil.move("G\\Source Codes\\bitirme\\" + apk_name_without_extension,"G:\\Documents\\Proje Kaynaklar\\Recompiled APKs")
    return dataset_features