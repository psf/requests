import pytest
from _pytest.main import Session
from _pytest.config import Config
from _pytest.config import get_config
from typing import List

def collect_marked_tests(mark_name: str, path: str = "") -> List[str]:
    config = pytest.Config.fromdictargs(
        {}, [path, "--collect-only", f"-m={mark_name}", "--disable-warnings", "-q"]
    )

    session = Session.from_config(config)
    session.perform_collect()

    # Ne garde que les tests qui ont effectivement ce mark
    marked_tests = []
    for item in session.items:
        if item.get_closest_marker(mark_name):
            marked_tests.append(item.nodeid)

    return marked_tests

if __name__ == "__main__":
    marked = collect_marked_tests("SPEC001")
    print(marked)


marked = collect_marked_tests("SPEC001")  # ← ici "slow" est la marque
print(marked)  # tu peux commenter ou supprimer cette ligne si tu ne veux rien afficher

print("\n \n")

def collect_marked_tests2(mark_name: str, path: str = "") -> List[str]:
    config = pytest.Config.fromdictargs(
        {}, [path, "--collect-only", "--disable-warnings"]
    )
    session = Session.from_config(config)
    session.perform_collect()

    marked_tests = []
    for item in session.items:
#        if item.get_closest_marker(mark_name):
        if any(mark.name == mark_name for mark in item.iter_markers()):

            marked_tests.append(item.nodeid)
    return marked_tests


marked2 = collect_marked_tests2("SPEC001")
print("Tests marqués SPEC001 :", marked2)



def collect_all_tests(path=""):
    config = pytest.Config.fromdictargs({}, [path, "--collect-only", "--disable-warnings"])
    session = Session.from_config(config)
    session.perform_collect()

    for item in session.items:
        print(f"Found test: {item.nodeid}")
        print("Marks:", [m.name for m in item.iter_markers()])

print(collect_all_tests())
