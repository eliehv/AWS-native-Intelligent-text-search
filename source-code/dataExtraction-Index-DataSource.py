"""
    The main process in this script includes:
        Extract data and put it in a specific formt
        load data in Amazon S3
        create Kendra index
        create data source (S3 is the data source in this case)
        sync the data source
        define proper IAM role and policies to be consumed by the created resources 
"""
import logging
import boto3
import botocore
from botocore.exceptions import ClientError
import os
import glob
import configparser
import re
import json
import requests
import unidecode
from bs4 import BeautifulSoup
from requests.exceptions import HTTPError
import pprint
import time

#**************** Read Config *************
def readConfig():
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    return config['Data-Metadata']

config = readConfig()

#**************** Create folder to store extracted data locally ********
def create_folder(folder_name):
    current_directory = os.getcwd()
    #folder_name = config['folder_name']
    final_directory = os.path.join(current_directory, r'{}'.format(folder_name))
    if not os.path.exists(final_directory):
       os.makedirs(final_directory)
    print('directory created to store the data files : {}'.format(final_directory))
    
#***************** Extract Data **********************
"""Extract nested values from a JSON tree.
    ******** Extract name and email address of author **********
"""
def json_extract_AuthorInfo(obj, key):
    """Recursively fetch values from nested JSON."""
    arr = []
    def extract(obj, arr,key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                arr.append(item)
                extract(item, arr, key)
        return arr

    values = extract(obj, arr, key)
    return values

def _getLinks(_header):
    children = _header.next_sibling.findChildren('a', recursive=True)
    links = [child.get('href') for child in children]
    return(links)


def _get_text(_header, headers):
    text = []
    while _header.next_sibling not in headers and _header.next_sibling:
        text.append(unidecode.unidecode(_header.next_sibling.text))
        _header = _header.next_sibling
    text = ' '.join(text)
    return(text)
"""
    store extrcated data and metadata files separately 
"""
def store_data_metadata_filesLocally(all_content, folder_name):
    
    for i in range(len(all_content)):
        data_dict = all_content[i]
        title = data_dict['title']
        title = "".join(c for c in title if c.isalpha() or c == ' ')
        
        data_file_name = f'{folder_name}/{title}.text'
        metadata_file_name = f'{folder_name}/{title}.text.metadata.json'
        
        with open(data_file_name, 'w') as f:
            file_content = data_dict['body']
            for d in file_content:
                for k,v in d.items():
                    if(k != 'header' and k !='text'):
                        f.write(k)
                    f.write('\n')
                    f.write(v)

        metadata_json_file = {}
        for key,val in data_dict.items():
            
            if key == 'author':
                metadata_json_file.update({'Author':val})
                
            if key == 'createdDate':
                metadata_json_file.update({'CreatedDate':val})
                
            if key == 'pageLink':
                metadata_json_file.update({'pageLink':val})
                
            if key == 'title':
                metadata_json_file.update({'title':val})
                
                
            # there was an error in syncing the data source due to _document_body attribute. 
            #I think the reason is type of stored data in this field, we stored dictionary (json file) 
            #while it is supposed to be string
            
            if key == 'body':
                body_text = []
                for body_item in val:
                    for body_k,body_v in body_item.items():
                        body_text.append(body_v)
                temp = "".join(body_text)
                metadata_json_file.update({'Body_content':temp})
                
            if key == 'type':
                metadata_json_file.update({'FileType':val})
                
            # else:            
        metadata_json_file.update({'_category':'EH'})
                
                
        metadata_json_file_all = {}
        metadata_json_file_all.update({'DocumentId':data_dict['id']})
        metadata_json_file_all.update({'Attributes':metadata_json_file})
        metadata_json_file_all.update({'Title':data_dict['title']})
        metadata_json_file_all.update({'ContentType':'PLAIN_TEXT'})
        
        with open(metadata_file_name, 'w', encoding = 'utf-8') as mf:
            #print(metadata_file_name)          
            mf.write(json.dumps(metadata_json_file_all,ensure_ascii=False))
            #json.dump(metadata_json_file_all, mf, ensure_ascii=False)
                       
""" 

    extract body text besides some metadata like author, uri, creation date, type, title from Employee Handbook
                                                                                                                        
""" 
def extract_data_metadata_EH(config):
    
    folder_name = config['folder_name']
    token =  config['token']
    limit =  1000  
    url = 'https://<Your url>/rest/api/content/?expand=body,parent,history,metadata.properties&limit={}'.format(limit)


    r = requests.get(url, auth=('<Your usr>',token))
    results = r.json()['results']
    titles = [x['title'] for x in results]

    print('number of Extracted pages: ' + str(len(results)))
    
    all_content = []
    for i in range(len(results)):
        content = {}
        for key,val in results[i].items():
            if key == 'id':
                content.update({'id':val})
            if key == 'type':
                content.update({'type':val})
            if key == 'title':
                content.update({'title':val})
            # name and email of author should be extarcted of a nested dict in history key
            if key == 'history':
                content.update({'createdDate':json_extract_AuthorInfo(results[0],'createdDate')[0]})
                #content.update({'author':{'Email':json_extract_AuthorInfo(results[0],'email')[0],
                                #'Name':json_extract_AuthorInfo(results[0],'publicName')[0]}})
                content.update({'author':json_extract_AuthorInfo(results[0],'email')[0]}) 


            # extract body of the document content and page link
            webui = results[i]['_links']['webui']
            textURL = f'https://<Your url>{webui}'
            r2 = requests.get(textURL,auth=('<Your usr>',token))
            soup=BeautifulSoup(r2.text,'html.parser')
            # look for pattern containing h1 to h6 in html (level 1 to 6 of headings)
            headers = soup.find_all(re.compile('^h[1-6]$'))

            txt = []#{}#''
            for h in headers:
                if h.next_sibling:
                    text = _get_text(h, headers)
                    txt.append({'header':h.text,
                                       'text':text})
                    refLinks = _getLinks(h)
            content.update({'pageLink': textURL})
            content.update({'body':txt})
            content.update({'pageLink':textURL})
        all_content.append(content)
    print("The number of Items Extarcted : {}".format(len(all_content)) )
    # call the method to store data and metadata locally
    store_data_metadata_filesLocally(all_content,folder_name)
    return all_content
        
"""
    ************  Create s3 bucket and store documents in it ***************
"""
def create_Bucket(config):

    bucket_name = config['bucket_name']
    aws_access_key_id= config['aws_access_key_id']
    aws_secret_access_key=config['aws_secret_access_key']
    region = config['region']
    bucket_exists = False
    """Create an S3 bucket in a specified region

    If a region is not specified, the bucket is created in the S3 default
    region (us-east-1).

    :param bucket_name: Bucket to create
    :param region: String region to create bucket in, e.g., 'us-west-2'
    :return: True if bucket created, else False
    """
    s3_client = boto3.client('s3', aws_access_key_id = aws_access_key_id, aws_secret_access_key = aws_secret_access_key)
    response = s3_client.list_buckets()
    for bucket in response['Buckets']:
        if bucket["Name"] == bucket_name:
            print(f'There already exists a bucket called {bucket["Name"]}')
            bucket_exists = True
            break
        

    # Create bucket
    if not bucket_exists:
        try:
            if region is None:
                #s3_client = boto3.client('s3',aws_access_key_id, aws_secret_access_key)
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client = boto3.client('s3', region_name=region)
                location = {'LocationConstraint': region}
                s3_client.create_bucket(Bucket=bucket_name,
                                        CreateBucketConfiguration=location)
        except ClientError as e:
            logging.error(e)
            return False
    return True


def upload_File(file_name, bucket, config, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    aws_access_key_id = config['aws_access_key_id']
    aws_secret_access_key = config['aws_secret_access_key']
    
    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    s3_client = boto3.client('s3',aws_access_key_id = aws_access_key_id, aws_secret_access_key= aws_secret_access_key)
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True

def put_data_to_S3(config):
    folder_name = config['folder_name']
    #print(folder_name)
    bucket_name = config['bucket_name']
    for filepath in glob.glob(os.path.join(folder_name, '*.*')):#glob.glob(os.path.join('data_metadata', '*.text')):
        #print(filepath)
        print('****** filePath : '+filepath)
        
        object_name = filepath.replace(' ', '-')
        upload_File(filepath, bucket_name, config, object_name)

"""
        *************   Create Index, data source to connect to and Synchronize data source ***************
"""
def createIndex(kendra, index_name, description, role_arn):

    print("Create an index with following detail ")
    print("index_name : "+index_name)
    print("Role ARN : "+role_arn)

    try:
        # NB if you Edition parameter is not set, it will be set to ***Enterprise*** by defaut
        index_response = kendra.create_index(
            Description = description,
            Name = index_name,
            RoleArn = role_arn,
            Edition='DEVELOPER_EDITION'
        )

        pprint.pprint(index_response)

        index_id = index_response["Id"]

        print("Wait for Kendra to create the index.")

        while True:
            # Get index description
            index_description = kendra.describe_index(
                Id = index_id
            )
            # If status is not CREATING quit
            status = index_description["Status"]
            print("    Creating index. Status: "+status)
            if status != "CREATING":
                break
            time.sleep(60)
        print("creating index ends.")
        return index_id
    
    except  ClientError as err:
            
            print("!!!!!!!!!!!\n%s" % err)
            print(err.response['Error']['Code'])
            print(err.response)
            print("an index with same name already exists!")

    print("Program ends.")

def createDataSource(kendra,bucket_name,data_source_description,
                     data_source_type,data_source_name,index_id,
                     data_source_role_arn):
    print("Create an S3 data source")

    configuration = {"S3Configuration":
        {
            "BucketName": bucket_name
        }
    }

    data_source_response=kendra.create_data_source(
        Configuration = configuration,
        Name = data_source_name,
        Description = data_source_description,
        RoleArn = data_source_role_arn,
        Type = data_source_type,

        IndexId = index_id
    )

    pprint.pprint(data_source_response)

    data_source_id = data_source_response["Id"]

    print("Wait for Kendra to create the data source.")

    while True:
        data_source_description = kendra.describe_data_source(
            Id = data_source_id,
            IndexId = index_id
        )
        # When status is not CREATING quit.
        status = data_source_description["Status"]
        print("    Creating data source. Status: "+status)
        time.sleep(60)
        if status != "CREATING":
            break

    print("Synchronize the data source.")
    return data_source_response
    
    
 #********** Sync the resource   
def sync_dataSource(kendra, data_source_id,index_id):
    sync_response = kendra.start_data_source_sync_job(
        Id = data_source_id,
        IndexId = index_id
    )

    pprint.pprint(sync_response)

    print("Wait for the data source to sync with the index.")

    while True:

        jobs = kendra.list_data_source_sync_jobs(
            Id=data_source_id,
            IndexId=index_id
        )

        # There should be exactly one job item in response
        status = jobs["History"][0]["Status"]

        print("    Syncing data source. Status: "+status)
        if status != "SYNCING":
            break
        time.sleep(60)
    return #sync_response


"""
      **************   IAM roles and policy management ***********
"""
iam_client = boto3.client('iam',aws_access_key_id= config['aws_access_key_id'],
    aws_secret_access_key=config['aws_secret_access_key'])

#A trust policy to allow Amazon Kendra to assume a role.
def create_Kendra_IAM_role():
    kendra_role ={
        'Version': '2012-10-17',
        'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'kendra.amazonaws.com'},#{'Service': service}
                'Action': 'sts:AssumeRole'
            } #for service in allowed_services
            
            
          
        ]
    }
    return kendra_role
    #role_file_name = 'kendra-role.json'
    #with open(role_file_name, 'w') as f:
        #f.write(json.dumps(kendra_role,ensure_ascii=False))
def create_role(iam_client, role_name,region,account_ID):
    """
    Creates a role that lets a list of specified services assume the role.

    :param role_name: The name of the role.
    :param allowed_services: The services that can assume the role.
    :return: The newly created role.
    """ 

    try:
        role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(create_Kendra_IAM_role()))
        
        #logger.info("Created role %s.", role.name)
        
    except botocore.exceptions.ClientError as error:
    # Put your error handling logic here
        #raise error
        if error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("User already exists")
            response = iam_client.list_roles()
            for r in response['Roles']:
                if r['RoleName'] == role_name:
                    return {'Role':r}
        else:
            print("Unexpected error: %s" % error)

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))

    else:
        return role
   
# define required policies

    
# ************** Policies needed to be attached to the role *************   
# index IAM role policy for index
def create_Index_Policy(region, account_ID):
    index_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "cloudwatch:PutMetricData",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "cloudwatch:namespace": "Kendra"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "logs:DescribeLogGroups",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:{}:{}:log-group:/aws/kendra/*".format(region,account_ID)
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogStreams",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:{}:{}:log-group:/aws/kendra/*:log-stream:*".format(region,account_ID)
        }
    ]
    }
    return index_policy
    #indexRole_file_name = 'index_role_policy.json'
    #with open(indexRole_file_name, 'w') as f:
        #f.write(json.dumps(index_policy,ensure_ascii=False))
    
    
    
# ************ IAM role for S3 datasource ***********
def create_s3Datasource_Role_Policy(region,account_ID,index_id,bucket_name):
    kendra_s3Datasource_policy ={
    "Version": "2012-10-17",
    "Statement": [
         {
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::{}/*".format(bucket_name)
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::{}".format(bucket_name)
            ],
            "Effect": "Allow"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kendra:BatchPutDocument",
                "kendra:BatchDeleteDocument"
            ],
            "Resource": [
                "arn:aws:kendra:{}:{}:index/{}".format(region,account_ID,index_id)
            ]
        }
    ]
    }
    return kendra_s3Datasource_policy

#     main()
def main():
    # Main Method (Run the pipeline)
    config = readConfig()
    
    #********** Extract data and metadata then store them locally and in s3
    folder_name = config['folder_name']
    create_folder(folder_name)
    all_content = extract_data_metadata_EH(config)
    
    create_Bucket(config)
    put_data_to_S3(config)
    
    #********* Create Policy and attach it to the Role ************
    policy_Name = config['kendra-index-policy-name']
    region = config['region']
    account_ID = config['account_ID']
    bucket_name = config['bucket_name']
    role_name = config['kendra_role_name']
    
    
    #******** create role ****************
    role = create_role(iam_client, role_name,region,account_ID)
    print(role['Role']['RoleName'])
    
    #********* Get Policy ********** 
    response = iam_client.get_policy(
        PolicyArn='arn:aws:iam::{}:policy/{}'.format(account_ID,policy_Name)#kendra-index-policy-062022
    )
    #print(response['Policy'])
    
    if not response['Policy'] :
    
        #******** Create policy ******
        response = iam_client.create_policy(
              PolicyName=policy_Name,
              PolicyDocument=json.dumps(create_Index_Policy(region,account_ID))
                )
        print(response)
    if response['Policy']['AttachmentCount'] == 0:
        #******** Attach policy to the role *******
        print(role['Role']['Arn'])
        response = iam_client.attach_role_policy(
            PolicyArn=response['Policy']['Arn'],
            RoleName= role['Role']['RoleName']
            )
        print(response)
        
    #********* create kendra index ***********
    print('it is time to create Kendra index ...')
    kendra = boto3.client("kendra",  aws_access_key_id= config['aws_access_key_id'],
                                            aws_secret_access_key=config['aws_secret_access_key'])
    
    response = kendra.list_indices()
    print("list indecies response : ",response)
    
    if not response['IndexConfigurationSummaryItems']:
        
        session = boto3.session.Session()
        current_region = session.region_name
        print('\nCreating index  in ' + current_region)
    
        index_name = config['index_name']
        description = config['description']
        region = config['region']
        account_ID = config['account_ID']
    
        kendra_role_name =role['Role']['RoleName']# config['kendra_role_name']
    
        role_arn = role['Role']['Arn']#config['role_arn']
    
        index_id = createIndex (kendra, index_name, description, role_arn)
        print("The created index can be accessed with id : "+str(index_id))
    
    
        config = configparser.ConfigParser()
        config.read('config.ini')
        config.set('Data-Metadata-S3', 'index_id',index_id)
    
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
    else:
        for ind in response['IndexConfigurationSummaryItems']:
            print("\n\n ******************** index *************")
            print("already there is a index with name  and ID  created at ",
              ind['Name'],ind['Id'],ind['CreatedAt'])
            print("*****************")
    
    
    config = readConfig()
    
    
    
    
    #******** Create policy for s3 data source ******  
    dataSource_role_name = config['dataSource_role_name']
    print("data source role name : ",dataSource_role_name)
    
    #******** create role ****************
    dataSource_role = create_role(iam_client, dataSource_role_name,region,account_ID)
    print("data role name and ARN ",dataSource_role['Role']['RoleName'],dataSource_role['Role']['Arn'])
    
    #********* Get Policy ********** 
    
    policy_s3Datasource_Name = config['policy_s3Datasource_Name']
    response = iam_client.get_policy(
        PolicyArn='arn:aws:iam::{}:policy/{}'.format(account_ID,policy_s3Datasource_Name)
    )
    #print("get policy response ",response['Policy'])
    
    if not response['Policy'] :
    
        #******** Create policy ******
        response = iam_client.create_policy(
              PolicyName=policy_s3Datasource_Name,
              PolicyDocument=json.dumps(create_s3Datasource_Role_Policy(region,account_ID,index_id,bucket_name))
                )
        #print("data source policy creation response",response)
    if response['Policy']['AttachmentCount'] == 0:
        #******** Attach policy to the role *******
        #print(role['Role']['Arn'])
        response = iam_client.attach_role_policy(
            PolicyArn=response['Policy']['Arn'],
            RoleName= dataSource_role['Role']['RoleName']
            )
        #print("data source policy attachment response ",response)
    
    
    # ************ create s3 Data Source *********
    
    data_source_name = config['data_source_name']
    data_source_description = config['data_source_description']
    bucket_name = bucket_name
    data_source_type = "S3"
    data_source_role_arn = dataSource_role['Role']['Arn']
    index_id = config['index_id']
    
    
    response = kendra.list_data_sources(IndexId = index_id)
    #print("list data source response ",response)
    #if not response['SummaryItems']:
    data_source_response = createDataSource(kendra,bucket_name,data_source_description,
                         data_source_type,data_source_name,index_id,
                         data_source_role_arn)
    data_source_id = data_source_response['Id']
        
    #else:
    #    for r in response['SummaryItems']:
    #        if r['Name'] == data_source_name:
    #            data_source_id = r['Id'] 
    print('data source id. : ',data_source_id)
    sync_dataSource(kendra, data_source_id,index_id)
    
    
main()