import pytest  
import requests  
from unittest.mock import patch  
from src.issuer_setup import main  
  
@pytest.mark.error  
def test_schema_already_exists():  
    with patch('requests.post') as mock_post, \
         patch('requests.get') as mock_get:  
  
        mock_post.return_value.status_code = 409  
        mock_post.return_value.text = "Schema already exists"  
  
        mock_get.return_value.status_code = 200  
        mock_get.return_value.json.return_value = {  
            "schema_ids": ["test-schema-id"]  
        }  
  
        main()
  
@pytest.mark.error  
def test_cred_def_already_exists():  
    with patch('requests.post') as mock_post, \
         patch('requests.get') as mock_get:  
  
        mock_post.side_effect = [  
            type('Mock', (), {'status_code': 200})(),  
            type('Mock', (), {'status_code': 409})()  
        ]  
  
        mock_get.return_value.status_code = 200  
        mock_get.return_value.json.return_value = {  
            "credential_definition_ids": ["test-cred-def-id"]  
        }  
  
        main()
  
@pytest.mark.error  
def test_did_not_registered():  
    with patch('requests.get') as mock_get:  
        mock_get.return_value.status_code = 404  
  
        main()


