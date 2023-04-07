"""
    the following code updates some of the Kendra features to show required attributes (metadata) on the results
"""
import boto3
import configparser
from botocore.exceptions import ClientError
def readConfig():
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    return config['Data-Metadata-S3']


config = readConfig()
aws_access_key_id= config['aws_access_key_id']
aws_secret_access_key=config['aws_secret_access_key']
index_id = config['index_id']
kendra = boto3.client('kendra',aws_access_key_id= aws_access_key_id,aws_secret_access_key=aws_secret_access_key)

DocMetadataConfigUpdate = [

     {
                'Name': 'pageLink',
                'Type': 'STRING_VALUE',
                'Search': {
                    'Facetable': True,
                    'Searchable': True,
                    'Displayable': True,
                    'Sortable': False
                }
            },
             {
                'Name': 'Body_content',
                'Type': 'STRING_VALUE',
         
                
                'Search': {
                    'Facetable': True,
                    'Searchable': True,
                    'Displayable': True,
                    'Sortable': True
                }
            },
             {
                'Name': 'FileType',
                'Type': 'STRING_VALUE',
               
                'Search': {
                    'Facetable': True,
                    'Searchable': True,
                    'Displayable': True,
                    'Sortable': True
                }
            },
     {
                'Name': 'CreatedDate',
                'Type': 'DATE_VALUE',
                
                'Search': {
                    'Facetable': True,
                    'Searchable': False,
                    'Displayable': True,
                    'Sortable': True
                }
            },
     {
                'Name': 'Author',
                'Type': 'STRING_VALUE',
                
                'Search': {
                    'Facetable': True,
                    'Searchable': False,
                    'Displayable': True,
                    'Sortable': True
                }
            },
     {
                'Name': '_category',
                'Type': 'STRING_VALUE',
                
                'Search': {
                    'Facetable': True,
                    'Searchable': True,
                    'Displayable': True,
                    'Sortable': False
                }
            }
        ]

try:
    response = kendra.update_index(
        Id=index_id,
        DocumentMetadataConfigurationUpdates= DocMetadataConfigUpdate
          
    )
except ClientError as err:
            
    print("!!!!!!!!!!!\n%s" % err)
    print(err.response['Error']['Code'])
    print(err.response)
