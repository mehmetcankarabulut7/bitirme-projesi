def get_feature_matrix_and_header_list():
    from extract_features import extractFeatures
    from write_file import print_global_rank
    # from write_file print_local_rank

    """
    features    : Her sınıftaki apk dosyalarının listesi (5 Elemanlı)
    features[0] : SMS listesi       (Uzunluğu SMS apk dosyaları kadar)
    features[1] : Adware listesi    (Uzunluğu Adware apk dosyaları kadar)
    features[2] : Banking listesi   (Uzunluğu Banking apk dosyaları kadar)
    features[3] : Riskware listesi  (Uzunluğu Riskware apk dosyaları kadar)
    features[4] : Benign listesi    (Uzunluğu Benign apk dosyaları kadar)

    features[0][N]      : (N+1). SMS apk dosyasının özellikleri         (7 Elemanlı)
    features[1][N]      : (N+1). Adware apk dosyasının özellikleri      (7 Elemanlı)
    features[2][N]      : (N+1). Banking apk dosyasının özellikleri     (7 Elemanlı)
    features[3][N]      : (N+1). Riskware apk dosyasının özellikleri    (7 Elemanlı)   
    features[4][N]      : (N+1). Benign apk dosyasının özellikleri      (7 Elemanlı) 

    features[0][N][0]   : (N+1). SMS apk dosyasının api call özelliğinin büyükten küçüğe sıralamasını tutan liste
    features[0][N][1]   : (N+1). SMS apk dosyasının permission özelliğinin büyükten küçüğe sıralamasını tutan liste
    features[0][N][2]   : (N+1). SMS apk dosyasının action özelliğinin büyükten küçüğe sıralamasını tutan liste
    features[0][N][3]   : (N+1). SMS apk dosyasının category özelliğinin büyükten küçüğe sıralamasını tutan liste
    features[0][N][4]   : (N+1). SMS apk dosyasının data özelliğinin büyükten küçüğe sıralamasını tutan liste
    features[0][N][5]   : (N+1). SMS apk dosyasının meta-data özelliğinin büyükten küçüğe sıralamasını tutan liste
    features[0][N][6]   : (N+1). SMS apk dosyasının sınıfı str olarak ( SMS/0,Adware/1,Banking/2,Riskware/3,Benign/4 )
    features[0][N][7]   : (N+1). SMS apk dosyasının ismi ( apk1,apk2,....,apkN )
    NOT : Her özellik kendi apk dosyasına göre sıralıdır, global sıralama yapmak, en çok kullanılanları seçmek gerek.
    """
    features = extractFeatures()

    """
    class_ranked_feature_list : her sınıf için, o sınıfa ait tüm özelliklerin kendi içinde sıralamasını tutar, 6 elemanlıdır
    class_ranked_feature_list[0] : bir sınıf için api_call özelliğinin sıralı halini tutan dictionary
    ...
    class_ranked_feature_list[5] : bir sınıf için meta_data özelliğinin sıralı halini tutan dictionary

    global_features_data : her sınıf için bir liste tutar, 5 elemanlıdır, listelerde kendi sınıfına ait özelliklerin sıralı olarak tutulduğu
                            dictionary yapısı vardır(class_ranked_feature_list)
    local_ranked_feature_data[0][0] : SMS sınıfına ait api_call sıralaması
    local_ranked_feature_data[0][1] : SMS sınıfına ait permission sıralaması
    ...
    local_ranked_feature_data[1][0] : Adware sınıfına ait api_call sıralaması
    local_ranked_feature_data[1][3] : Adware sınıfına ait action sıralaması
    ...
    local_ranked_feature_data[4][0] : Benign sınıfına ait api_call sıralaması
    local_ranked_feature_data[4][4] : Benign sınıfına ait data sıralaması
    """

    """
    local_ranked_feature_data = list()
    # local ranking
    feature_list = ["api_call", "permission", "action", "category", "data", "meta_data"]
    # class_list : [0-4] , [SMS,...,Benign]

    for class_list in features:
        class_ranked_feature_list = list()
        # count [0,5] , [api_call,...,meta_data]
        count = -1
        for feature in feature_list:
            count = count + 1
            feature_dict = {"feature": list(), "count": list()}
            # apk : list of ranked features for one apk
            for apk in class_list:
                # ftr_dct : [api_call,....,label]
                ftr_dct = apk[count]
                for i in range(len(ftr_dct[feature])):
                    ftr = ftr_dct[feature][i]
                    cnt = ftr_dct["count"][i]
                    try:
                        index = feature_dict["feature"].index(ftr)
                        feature_dict["count"][index] = feature_dict["count"][index] + cnt
                    except:
                        feature_dict["feature"].append(ftr)
                        feature_dict["count"].append(cnt)
            try:
                l1, l2 = (list(t) for t in zip(*sorted(zip(feature_dict["count"], feature_dict["feature"]))))
                feature_dict["feature"] = l2[::-1]
                feature_dict["count"] = l1[::-1]
            except:
                ...
            # print(str(count) + " -> " + str(len(feature_dict)))
            class_ranked_feature_list.append(feature_dict)
            # print(len(class_ranked_feature_list))
        local_ranked_feature_data.append(class_ranked_feature_list)

    # print
    print_local_rank(local_ranked_feature_data)
    """

    """
    ranked_dataset_features : tüm veriseti için çıkarılan özelliklerin sıralamasını tutar, 6 elemanlıdır

    ranked_dataset_features = list()
    for mck in range(6):
        ranked_feature_dct = {"feature": list(), "count": list()}
        for class_ranked in local_ranked_feature_data:
            for blt in range(len(class_ranked[mck]["feature"])):
                ftr = class_ranked[mck]["feature"][blt]
                cnt = class_ranked[mck]["count"][blt]
                try:
                    index = ranked_feature_dct["feature"].index(ftr)
                    ranked_feature_dct["count"][index] = ranked_feature_dct["count"][index] + cnt
                except:
                    ranked_feature_dct["feature"].append(ftr)
                    ranked_feature_dct["count"].append(cnt)
        try:
            l1, l2 = (list(t) for t in zip(*sorted(zip(ranked_feature_dct["count"], ranked_feature_dct["feature"]))))
            ranked_feature_dct["feature"] = l2[::-1]
            ranked_feature_dct["count"] = l1[::-1]
        except:
            ...
        ranked_dataset_features.append(ranked_feature_dct)
    """

    feature_list = ["api_call", "permission", "action", "category", "data", "meta_data"]
    # müsvedde
    ranked_dataset_features = list()
    for mck in range(6):
        xyz = 0
        ranked_feature_dct = {"feature": list(), "count": list()}
        for class_list in features:
            for apk in class_list:
                xyz = xyz + 1
                sd = feature_list[mck]
                print("calculating : " + sd + " -> " + str(xyz))
                for blt in range(len(apk[mck][sd])):
                    ftr = apk[mck][sd][blt]
                    cnt = apk[mck]["count"][blt]
                    ww = ranked_feature_dct["feature"]
                    qw = ranked_feature_dct["count"]
                    try:
                        index = ww.index(ftr)
                        qw[index] = qw[index] + cnt
                    except:
                        ww.append(ftr)
                        qw.append(cnt)
        try:
            l1, l2 = (list(t) for t in
                      zip(*sorted(zip(ranked_feature_dct["count"], ranked_feature_dct["feature"]))))
            ranked_feature_dct["feature"] = l2[::-1]
            ranked_feature_dct["count"] = l1[::-1]
        except:
            ...
        ranked_dataset_features.append(ranked_feature_dct)
    # müsvedde
    # print
    print_global_rank(ranked_dataset_features)

    header_list = ["name", "label"]
    header_api_call = ranked_dataset_features[0]["feature"][:300]
    header_list.extend(header_api_call)

    header_permission = ranked_dataset_features[1]["feature"][:100]
    header_list.extend(header_permission)

    header_action = ranked_dataset_features[2]["feature"][:100]
    header_list.extend(header_action)

    header_category = ranked_dataset_features[3]["feature"][:25]
    header_list.extend(header_category)

    header_data = ranked_dataset_features[4]["feature"][:100]
    header_list.extend(header_data)

    header_meta_data = ranked_dataset_features[5]["feature"][:100]
    header_list.extend(header_meta_data)
    """
    bu değişken bir listedir, matris değildir
    header_list[0] = "name"
    header_list[1] = "label"
    header_list[2] = api_call list      -> header_api_call
    header_list[3] = permission list    -> header_permission
    header_list[4] = action list        -> header_action
    header_list[5] = category list      -> header_category
    header_list[6] = data list          -> header data
    header_list[7] = meta data list     -> headear meta data
    """
    # create feature vector
    feature_matrix = list()
    als = 0
    for apks_class_list in features:
        # apk_feature_list -> [0,6]
        for apk_feature_list in apks_class_list:
            feature_vector = list()
            # append name -> index 7
            als = als + 1
            print("calculating feature vector for " + str(als))
            feature_vector.append(apk_feature_list[7])
            # append label -> index 6
            feature_vector.append(apk_feature_list[6])
            # append api_call -> index 0
            for h_call in header_api_call:
                try:
                    index = apk_feature_list[0]["api_call"].index(h_call)
                    count_of_item = apk_feature_list[0]["count"][index]
                    feature_vector.append(count_of_item)
                except:
                    feature_vector.append(0)
            # append permission -> index 1
            for h_permission in header_permission:
                try:
                    index = apk_feature_list[1]["permission"].index(h_permission)
                    count_of_item = apk_feature_list[1]["count"][index]
                    feature_vector.append(count_of_item)
                except:
                    feature_vector.append(0)
            # append action -> index 2
            for h_act in header_action:
                try:
                    index = apk_feature_list[2]["action"].index(h_act)
                    count_of_item = apk_feature_list[2]["count"][index]
                    feature_vector.append(count_of_item)
                except:
                    feature_vector.append(0)
            # append category -> index 3
            for h_ctg in header_category:
                try:
                    index = apk_feature_list[3]["category"].index(h_ctg)
                    count_of_item = apk_feature_list[3]["count"][index]
                    feature_vector.append(count_of_item)
                except:
                    feature_vector.append(0)
            # append data -> index 4
            for h_data in header_data:
                try:
                    index = apk_feature_list[4]["data"].index(h_data)
                    count_of_item = apk_feature_list[4]["count"][index]
                    feature_vector.append(count_of_item)
                except:
                    feature_vector.append(0)
            # append meta_data -> index 5
            for h_m_data in header_meta_data:
                try:
                    index = apk_feature_list[5]["meta_data"].index(h_m_data)
                    count_of_item = apk_feature_list[5]["count"][index]
                    feature_vector.append(count_of_item)
                except:
                    feature_vector.append(0)
            feature_matrix.append(feature_vector)
    print("calculation finished.")
    return feature_matrix, header_list