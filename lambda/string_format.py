import json
import boto3
import os

sns = boto3.client('sns')

def lambda_handler(event, context):
    detail = event['detail']
    project_name = detail.get('project-name', 'N/A')
    status = detail.get('build-status', 'N/A')
    log_link = detail.get('additional-information', {}).get('logs', {}).get('deep-link', 'N/A')
    time = event.get('time', 'N/A')

    message = f"""📣 CodeBuild 알림

🔧 프로젝트: {project_name}
📅 시간: {time}
📌 상태: {status}
🔍 로그 보기: {log_link}
"""

    response = sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Subject=f"[CodeBuild] {project_name} - {status}",
        Message=message
    )
    return {"status": "ok", "sns_response": response}
