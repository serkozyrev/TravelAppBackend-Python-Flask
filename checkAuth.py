import jwt, os
jwtsecret = os.getenv('jwtsecret')


def auth(token):
    decodedToken = jwt.decode(token, jwtsecret, algorithms=["HS256", ])
    return decodedToken['id']