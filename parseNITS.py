import json
from ConvertToDict import convert_to_list
from multiprocessing import Pool
from DictDivide import even_divide
import threading
from findCVEinfile import del_patterns



def parse(CVEs):
    lst = []
    f = open(CVEs, "rt")
    data = f.read()
    words = data.split()
    a = 0
    for m in range(((len(words)*3)-1)):
        if m % 2 != 0:
            c = 0 + a
            f = open(CVEs, "rt")
            data = f.read()
            word = data.split()
            words = data.split("-")
            with open(CVEs, 'r') as f:
                y = words[m]
            if(int(y) == 1999 or int(y) == 1999 or int(y) == 1999):
                y = 2002
            print(y)
            NITSBD = '/home/pavel/PycharmProjects/Vulnerabilities/data/Nist_DB/nvdcve-1.1-'+ str(y) +'.json'
            n = del_patterns(word[c])
            print(c)
            print(n)
            file = open(NITSBD, "r")
            example = file.read()
            file.close()
            BT = json.loads(example)
            for i in range(len(BT["CVE_Items"])):
                try:
                    if BT["CVE_Items"][i]['cve']['CVE_data_meta']['ID'] == n:
                        output = (
                            {
                            n : BT["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]['vectorString']
                            }
                        )
                        with open('temp4.json', mode='w') as f:
                            lst.append(output)
                            json.dump(lst, f, ensure_ascii=False, indent=4)
                    if(BT["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]['vectorString'] != "nan" and BT["CVE_Items"][i]['cve']['CVE_data_meta']['ID'] == n):
                        output1 = (
                            {
                            n + "-CVSSV3" : BT["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]['vectorString']
                            }
                        )
                        with open('temp5.json', mode='w') as f:
                            lst.append(output1)
                            json.dump(lst, f, ensure_ascii=False, indent=4)
                except KeyError:
                    pass
            a = a + 1
    convert_to_list("temp4.json")
    convert_to_list("temp5.json")

BT1 = open("CVELIST1.txt", "rt")
data1 = BT1.read()
words1 = data1.split()

if __name__ == '__main__':
    thread1 = threading.Thread(target=parse, args=('CVELIST0.txt',))
    thread2 = threading.Thread(target=parse, args=('CVELIST1.txt',))
    thread3 = threading.Thread(target=parse, args=('CVELIST2.txt',))
    thread4 = threading.Thread(target=parse, args=('CVELIST3.txt',))

thread1.start()
thread2.start()
thread3.start()
thread4.start()
thread1.join()
thread2.join()
thread3.join()
thread4.join()