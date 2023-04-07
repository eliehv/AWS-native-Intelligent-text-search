"""
    To search through the created Kendra index, we need to send the user queries to that
    So, in the proposed solution we used API Gateway to invoke the lambda to query the Kendra index.
    in this scrip  the user question will be received from Slack and then the request is sent to the Kendra 
    and the returned result will be sent back to Slack.
"""

import os
import io
import json
import boto3
import slack, certifi
import ssl as ssl_lib
from random import choices
from collections import OrderedDict

from slack_sdk import WebClient
#from slack_sdk.errors import SlackApiError

token = os.environ['TOKEN']
#print(token)
ssl_context = ssl_lib.create_default_context(cafile=certifi.where())
slack_client = WebClient(token=token, ssl=ssl_context)


kendra_client= boto3.client('kendra')
index_id = os.environ['index_id']

def lambda_handler(event, context):
    #Handle an incoming HTTP request from a Slack chat-bot.
    
    print(event)  # For checking the event in cloudwatch logs
    
    def usr_message(message, channel):
        response = slack_client.chat_postMessage(
            channel=channel,
            text=message
        )
        return response.status_code

    user_id = event['event']['user']
    channel = event['event']['channel']

    t_user_message = event['event']['blocks'][0]['elements'][0]['elements']
    user_message1 = ''

    for i in t_user_message:
        if 'text' in i:
            i['text'] = i['text'].replace(u'\xa0', u' ')
            user_message1 = user_message1 + i['text']
    user_message = user_message1.strip().lower()
    user_message = user_message.replace(u'“', u'"')
    user_message = user_message.replace(u'”', u'"')
    print(f'''User {user_id} Requesting app from channel {channel}''')
    print(user_message)

    kendra_response = kendra_client.query(QueryText = user_message, IndexId = index_id)
   

    print ('\nSearch results for query: ' + user_message + '\n')  
    
    print("response : {}".format(kendra_response))
    
    result_array = []
    
    for query_result in kendra_response['ResultItems']:

        print('-------------------')
        print('Type: ' + str(query_result['Type']))

        if query_result['Type']=='ANSWER' or query_result['Type'] == 'QUESTION_ANSWER':
            answer_text = query_result['DocumentExcerpt']['Text']
            print(answer_text)
            result = answer_text

        if query_result['Type']=='DOCUMENT':
            if 'DocumentTitle' in query_result:
                document_title = query_result['DocumentTitle']['Text']
                print('Title: ' + document_title)
            document_text = query_result['DocumentExcerpt']['Text']
            print(document_text)
            print(query_result['DocumentTitle'])
            print(query_result['DocumentURI'])
            #print(query_result['AdditionalAttributes'])
            print('************  DocumentAttributes  Find Source URI ***************')
            print( query_result['DocumentAttributes'] )
            result = document_text + '\n' 
            #+ query_result['DocumentURI'] + '\n'# document_title + "\n" + document_text #+ '\n' + query_result['DocumentURI']
            result_array.append(result)
        
        print ('------------------\n\n')  
    ######slack_client.conversations_leave()
    print('response ***')
    if kendra_response['ResultItems']:
        print(result)
    else:
        print('no result form query')
        result = 'no result form query'
    if user_message == 'Hi' or user_message=='hello' or user_message=='hei' or user_message=='Hey':
        return_message = f'''Hello <@{user_id}>, I am <Your search engine name>, here to help you ... '''
        slack_res = usr_message(return_message, channel)
    else:
        
        #return_message =  "<@{}> {} ".format(user_id, result)
        return_message =  "<@{}> ".format(user_id)
        return_message = return_message + "\n" + result_array[0]
        result_array.pop(0)
        slack_res = usr_message(return_message, channel)
        return_message = "\n -------------------------------------\n other proper responses: \n"
        for res in result_array:
            return_message = return_message + "\n" + res + "------------------------------------- \n"
        slack_res = usr_message(return_message, channel)
    print({'user_id':user_id, 'user_message': user_message, 'bot_message': result})
    return result




