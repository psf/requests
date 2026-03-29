import os
import zipfile

import pytest

import requests


class TestMergeEnvironmentSettings:
    def test_verify_unchanged_for_regular_path(self, tmp_path):
        """Non-zip paths are returned as-is."""
        ca_bundle = tmp_path / "cacert.pem"
        ca_bundle.write_bytes(b"fake cert")
        s = requests.Session()
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("REQUESTS_CA_BUNDLE", str(ca_bundle))
            settings = s.merge_environment_settings(
                "http://example.com", {}, False, True, None
            )
        assert settings["verify"] == str(ca_bundle)

    def test_verify_extracted_from_zip(self, tmp_path):
        """CA bundles inside zip archives are extracted to a real file."""
        ca_content = b"fake cert content"

        zip_path = tmp_path / "bundle.zip"
        with zipfile.ZipFile(str(zip_path), "w") as zf:
            zf.writestr("cacert.pem", ca_content)

        zip_ca_path = os.path.join(str(zip_path), "cacert.pem")

        s = requests.Session()
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("REQUESTS_CA_BUNDLE", zip_ca_path)
            settings = s.merge_environment_settings(
                "http://example.com", {}, False, True, None
            )

        verify = settings["verify"]
        assert verify != zip_ca_path
        assert os.path.exists(verify)
        with open(verify, "rb") as f:
            assert f.read() == ca_content
