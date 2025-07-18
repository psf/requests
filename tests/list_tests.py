
#import subprocess
#import pytest

#result = subprocess.run(["pytest", "--collect-only"], capture_output=True, text=True)
#print(result.stdout)

import pytest
#import os
import doorstop
import re

text = "Learning Python is fun"
pattern = "Python"
match = re.search(pattern, text)

if match:
    print("Found:", match.group())
else:
    print("Not found")

def speci(text):
#    match=re.search("SPEC\d\d\d ",text)
    match=re.fullmatch(r"SPEC\d\d\d",text)

    if match:
#        if len(re.findall("\d", text))==3:
         return(1)
    return(0)


class Collector:
    def __init__(self):
        self.collected = []

#    def pytest_collection_modifyitems(self, session, config, items):
#        self.collected = [item.nodeid for item in items]
    def pytest_collection_modifyitems(self, items):

        for item in items:

            self.collected.append(item.nodeid)
       # print(self.collected)


class Collector2:

    def __init__(self):
        self.collected = set()

    def pytest_collection_modifyitems(self, items):

        for item in items:
            for mark in item.iter_markers():
            #marks = [mark.name for mark in item.iter_markers()]
            #print(f"{item.nodeid} -> {marks}")
                if speci(mark.name)==1:
                    self.collected.add(mark.name)



def run_pytest_collect_nodeids(test_dir):
    plugin = Collector()
    pytest.main(["-v", test_dir], plugins=[plugin])
    return plugin.collected

def run_pytest_marker(mark, test_dir="" ):
    plugin = Collector()
    pytest.main(["-m", mark, test_dir], plugins=[plugin])
    return plugin.collected

def run_pytest_collect_nodeids_mark(mark, test_dir=""):
    plugin = Collector()
    session=pytest.main(["--collect-only","-q","--disable-warnings","-m",mark, test_dir], plugins=[plugin])
#    pytest.main(["--collect-only","-m",mark, test_dir], plugins=[plugin])
#    return plugin.collected
    return session

def run_pytest_collect2(test_dir=""):
    marks=Collector2()
    pytest.main(["--collect-only","--tb=no","-q","-m YAPAS", test_dir], plugins=[marks])
    return (marks.collected)

def get_doorstop_specifications(root_path):

    tree = doorstop.build(root=root_path)
    

    specifications = []

    for doc in tree:
        print(f"Document : {doc.prefix}, items : {len(doc.items)}")
        for item in doc.items:
            spec = {
                "uid": str(item.uid),
                "doctype": doc.prefix,
                "text": str(item.text).strip(),
                "path": str(item.path),
                "level": item.level,
                "derived": item.derived,
                "links": [str(link) for link in item.links] 
            }
            specifications.append(spec)

    return specifications

def get_doorstop_uid(root_path):
    tree = doorstop.build(root=root_path)

    specifications = set()

    for doc in tree:
        for item in doc.items:
           if speci(str(item.uid)):
               specifications.add(str(item.uid))
    return specifications






# Exemple d'utilisation


#liste = run_pytest_collect_nodeids("./test_requests.py")
#liste = run_pytest_collect_nodeids_mark("SPEC001")


#print("Tests exécutés :", liste)
#print(len(liste))
#liste2 = run_pytest_marker("SPEC001")
#liste3=get_doorstop_specifications("../req")
#liste4=run_pytest_collect2()
liste5=get_doorstop_uid("../req")

#print(liste2)
for elt in liste5:
	print (elt)

texte="SPEC002"
print("\n",texte)
print(speci(texte))

#conversion de la liste en str
#str_liste="\n".join(liste3)
#print (str_liste)
