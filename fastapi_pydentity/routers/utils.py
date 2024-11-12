def http_exception_openapi_scheme(description, detail):
    return {
        'content': {
            'application/json': {
                'example': {
                    'detail': detail
                }
            }
        },
        'description': description
    }
