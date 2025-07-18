import pytest
from pathlib import Path

 
def list_tests_simple(directory):

      """Simple test listing using pytest collection"""

      config = pytest.Config.fromdictargs({}, [str(Path(directory))])

      session = pytest.Session.from_config(config)

      session.collect()

      print('a') 

      for item in session.items:


          marks = [mark.name for mark in item.iter_markers()]

          print(f"{item.nodeid} | Marks: {', '.join(marks) if marks else 'None'}")

 

  # Usage
list_tests_simple("./home/vboxuser/requests")

 

 




#import pytest

 

  # One-liner to get all test items

def get_tests(directory):

      session = pytest.Session.from_config(pytest.Config.fromdictargs({}, [directory]))

      session.collect()

      return [(item.nodeid, [m.name for m in item.iter_markers()]) for item in session.items]

 

  # Usage

tests = get_tests("")

#print(tests)

for name, marks in tests:

      print(f"{name} | {marks}")
      print('a')
