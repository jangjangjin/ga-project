import json
import boto3

def lambda_handler(event, context):
    sns = boto3.client('sns')
    
    detail = event['detail']
    project_name = detail.get('project-name', 'N/A')
    status = detail.get('build-status', 'N/A')
    time = event.get('time', 'N/A')
    log_link = detail.get('additional-information', {}).get('logs', {}).get('deep-link', 'N/A')

    msg = f"""
    📢 CodeBuild Notification

    🧱 Project: {project_name}
    🟢 Status: {status}
    🕐 Time: {time}
    🔗 Logs: {log_link}
    """

    sns.publish(
        TopicArn='arn:aws:sns:ap-northeast-2:xxx:SnsTopicCodeBuild',
        Subject=f"[CodeBuild] {project_name} - {status}",
        Message=msg
    )
