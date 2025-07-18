import pytest
import doorstop
import re

def reg_exp_speci(text):
    match=re.fullmatch(r"SPEC\d\d\d",text)
    if match:
         return(1)
    return(0)


class Collector_mark:

    def __init__(self):
        self.collected = set()

    def pytest_collection_modifyitems(self, items):
        for item in items:
            for mark in item.iter_markers():
                if reg_exp_speci(mark.name):
                    self.collected.add(mark.name)


def run_pytest_collect_mark(test_dir):
    marks=Collector_mark()
    pytest.main(["--collect-only","--tb=no","-q","-m YAPAS", test_dir], plugins=[marks])
    return (marks.collected)




def get_doorstop_uid(root_path):
    tree = doorstop.build(root=root_path)

    specifications = set()

    for doc in tree:
        for item in doc.items:
           if reg_exp_speci(str(item.uid)):
               specifications.add(str(item.uid))
    return specifications



def compare_sets(a,b):
    if (a & b)==set():
       print ("All checked")
    else:
       print ("nothing" if (a-b)==set() else a-b, "is missing in doorstop","\n","nothing" if (b-a)==set() else b-a, "is missing in pytest.markers")



def check_specs_doorstop_pytest(path=""):
    a= (run_pytest_collect_mark(path))
    b= (get_doorstop_uid(path))
    compare_sets(a,b)



check_specs_doorstop_pytest()
