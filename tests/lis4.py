
import pytest

 

def list_tests_simple(directory: str):

      """Simple test listing using direct pytest collection"""

      config = pytest.Config.fromdictargs({}, [])

      session = pytest.Session.from_config(config)

 

      # Collect from the directory

      collector = session.perform_collect([directory], genitems=False)[0]

 

      def walk_items(item):
          print (item)
          if hasattr(item, 'runtest'):  # It's a test item

              marks = [mark.name for mark in item.iter_markers()]

              print(f"{item.nodeid} | Marks: {', '.join(marks) if marks else 'None'}")

 

          # Recursively walk children

          for child in getattr(item, 'collect', lambda: [])():

              walk_items(child)

 

      walk_items(collector)

 

  # Uage
list_tests_simple(".")
