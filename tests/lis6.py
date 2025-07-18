import sys

import pytest

 

class MyPlugin:

    def __init__(self):
        self.collected = []

    def pytest_collection_modifyitems(self, items):
        print("\n +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n \n \n")
        for item in items:
            self.collected.append(item.nodeid)
        print(self.collected)
        print("\n +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n \n \n")
 
class MyPlugin2:

    def __init__(self):
        self.collected = set()

    def pytest_collection_modifyitems(self, items):
        print("\n +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n \n \n")
        for item in items:
            for mark in item.iter_markers():
            #marks = [mark.name for mark in item.iter_markers()]
            #print(f"{item.nodeid} -> {marks}")

                self.collected.add(mark.name)
        print(self.collected)
        print("\n +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n \n \n")

 

my_plugin = MyPlugin2()

directory = sys.argv[1] #convention linux

pytest.main(['--collect-only','-qs', directory], plugins=[my_plugin])


print("\n +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n \n \n")
 
print (my_plugin.collected)
#for nodeid in my_plugin.collected:

#    print(nodeid)
