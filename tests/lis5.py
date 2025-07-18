import pytest

 
def list_tests_simple(directory: str):

      """Simple test listing using direct pytest collection"""

      config = pytest.Config.fromdictargs({}, [directory])

      session = pytest.Session.from_config(config)

      session.perform_collect()

 

      for item in session.items:

          marks = [mark.name for mark in item.iter_markers()]

          print(f"{item.nodeid} | Marks: {', '.join(marks) if marks else 'None'}")

 

  # Usage

list_tests_simple("")
