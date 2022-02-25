from get_headers import get_feature_matrix_and_header_list
from numpy import asarray
from numpy import savetxt

feature_matrix, header_list = get_feature_matrix_and_header_list()
combined = list()
q = 0
combined.append(header_list)
for row in feature_matrix:
    q = q + 1
    print("combined " + str(q))
    combined.append(row)
print("printing csv file..")
data = asarray(combined)
savetxt("P:\\Proje Kaynaklar\\Veriseti\\features2.csv", data, delimiter=",", fmt="% s")