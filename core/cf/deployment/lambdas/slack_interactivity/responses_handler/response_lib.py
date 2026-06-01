import json

def success(body):
    return buildResponse(200, body)

def failure(body):
    return buildResponse(500, body)

def buildResponse(statusCode, body):
    return {
        'statusCode': statusCode,
        'headers': {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": True
        },
        'body': json.dumps(body)
    }
