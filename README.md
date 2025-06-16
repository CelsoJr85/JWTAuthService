# 🔐 JWT Auth Service

Serviço de autenticação JWT reutilizável em Python com suporte a access/refresh tokens, hash bcrypt de senhas e verificação segura. Compatível com FastAPI, Flask e uso standalone.

## 🚀 Instalação

### 1. Clone o repositório
```bash
git clone https://github.com/CelsoJr85/JWTAuthService.git
cd jwt-auth-service
```

### 2. Instale as dependências
```bash
pip install -r requirements.txt
```

Ou instale manualmente:
```bash
pip install pyjwt[crypto] passlib[bcrypt] python-multipart
```

### 3. Copie o arquivo para seu projeto
```bash
# Copie o arquivo JWTAuthService.py para sua pasta de projeto
cp JWTAuthService.py /caminho/do/seu/projeto/
```

## 📖 Uso Básico

### Importar e configurar
```python
from JWTAuthService import JWTAuthService

# Configuração básica
auth = JWTAuthService(
    secret_key="sua-chave-secreta-aqui",
    access_token_expire_minutes=30,
    refresh_token_expire_days=7
)
```

### Hash de senhas
```python
# Criar hash da senha
password = "minha_senha_123"
hashed_password = auth.hash_password(password)

# Verificar senha
is_valid = auth.verify_password(password, hashed_password)
print(f"Senha válida: {is_valid}")  # True
```

### Gerar tokens
```python
# Dados do usuário
user_data = {
    "user_id": 123,
    "email": "usuario@exemplo.com",
    "role": "admin"
}

# Criar access e refresh tokens
tokens = auth.create_token_pair(user_data)
print(tokens)
# {
#     "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
#     "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
#     "token_type": "bearer"
# }
```

### Verificar tokens
```python
# Verificar access token
payload = auth.verify_token(tokens["access_token"])
if payload.get("error"):
    print(f"Token inválido: {payload['error']}")
else:
    print(f"Usuário: {payload['email']}")
```

### Refresh token
```python
# Gerar novo access token usando refresh token
new_access_token = auth.refresh_access_token(tokens["refresh_token"])
if new_access_token:
    print("Novo access token gerado!")
else:
    print("Refresh token inválido ou expirado")
```

## 🌐 Exemplos com Frameworks

### FastAPI
```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from JWTAuthService import JWTAuthService

app = FastAPI()
security = HTTPBearer()
auth = JWTAuthService(secret_key="sua-chave-secreta")

@app.post("/login")
def login(email: str, password: str):
    # Aqui você validaria as credenciais no banco de dados
    # user = get_user_by_email(email)
    # if not user or not auth.verify_password(password, user.hashed_password):
    #     raise HTTPException(401, "Credenciais inválidas")
    
    tokens = auth.create_token_pair({
        "user_id": 1,
        "email": email,
        "role": "user"
    })
    return tokens

@app.get("/protected")
def protected_route(token: str = Depends(security)):
    payload = auth.verify_token(token.credentials)
    if payload.get("error"):
        raise HTTPException(401, "Token inválido")
    return {"message": f"Olá {payload['email']}!"}

@app.post("/refresh")
def refresh_token(refresh_token: str):
    new_token = auth.refresh_access_token(refresh_token)
    if not new_token:
        raise HTTPException(401, "Refresh token inválido")
    return {"access_token": new_token, "token_type": "bearer"}
```

### Flask
```python
from flask import Flask, request, jsonify
from functools import wraps
from JWTAuthService import JWTAuthService

app = Flask(__name__)
auth = JWTAuthService(secret_key="sua-chave-secreta")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token não fornecido'}), 401
        
        token = token.split(' ')[1]
        payload = auth.verify_token(token)
        if payload.get('error'):
            return jsonify({'error': 'Token inválido'}), 401
        
        return f(current_user=payload, *args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    # Validar credenciais aqui
    
    tokens = auth.create_token_pair({
        "user_id": 1,
        "email": data['email'],
        "role": "user"
    })
    return jsonify(tokens)

@app.route('/protected')
@token_required
def protected_route(current_user):
    return jsonify({
        "message": f"Olá {current_user['email']}!",
        "user": current_user
    })

@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.json
    new_token = auth.refresh_access_token(data['refresh_token'])
    if not new_token:
        return jsonify({'error': 'Refresh token inválido'}), 401
    return jsonify({"access_token": new_token, "token_type": "bearer"})
```

### Uso Standalone
```python
from jwt_auth_service import JWTAuthService

# Configurar serviço
auth = JWTAuthService()

# Simular cadastro de usuário
def register_user(email, password):
    hashed_password = auth.hash_password(password)
    # Salvar no banco: save_user(email, hashed_password)
    return {"email": email, "hashed_password": hashed_password}

# Simular login
def login_user(email, password, stored_hash):
    if auth.verify_password(password, stored_hash):
        return auth.create_token_pair({
            "user_id": 1,
            "email": email
        })
    return None

# Exemplo de uso
user = register_user("test@email.com", "123456")
tokens = login_user("test@email.com", "123456", user["hashed_password"])

if tokens:
    print("Login realizado com sucesso!")
    print(f"Access Token: {tokens['access_token'][:50]}...")
```

## 🔧 Configurações Avançadas

### Personalizar tempos de expiração
```python
auth = JWTAuthService(
    secret_key="sua-chave-super-secreta",
    access_token_expire_minutes=15,  # Token de acesso expira em 15 min
    refresh_token_expire_days=30     # Refresh token expira em 30 dias
)
```

### Usar com chave secreta do ambiente
```python
import os
from jwt_auth_service import JWTAuthService

auth = JWTAuthService(
    secret_key=os.getenv("JWT_SECRET_KEY", "fallback-secret"),
    access_token_expire_minutes=int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
)
```

### Decorador personalizado
```python
from jwt_auth_service import jwt_required

auth = JWTAuthService()

@jwt_required(auth)
def minha_funcao_protegida(current_user):
    print(f"Usuário autenticado: {current_user['email']}")
    return {"status": "autorizado"}

# Usar com token
resultado = minha_funcao_protegida(token="seu-jwt-token-aqui")
```

## 📋 Funcionalidades

- ✅ **Hash seguro de senhas** usando bcrypt
- ✅ **Geração de JWT tokens** (access + refresh)
- ✅ **Verificação e decodificação** de tokens
- ✅ **Renovação automática** com refresh tokens
- ✅ **Decorador para proteção** de rotas
- ✅ **Configuração flexível** de expiração
- ✅ **Compatível** com FastAPI, Flask, Django
- ✅ **Pronto para produção** com bibliotecas seguras

## 🔒 Segurança

- **bcrypt**: Hash de senhas com salt automático
- **PyJWT**: Biblioteca confiável para JWT
- **Verificação de expiração**: Tokens com tempo limitado
- **Refresh tokens**: Renovação segura sem re-login
- **Assinatura HMAC**: Tokens assinados e verificáveis

## 📚 Dependências

```txt
pyjwt[crypto]
passlib[bcrypt]
python-multipart
```

**requirements.txt:**
```txt
pyjwt[crypto]
passlib[bcrypt]
python-multipart
```

## 🎮 Interface de Teste Interativa

Incluímos uma interface web completa para testar todas as funcionalidades do JWT Auth Service:

### Primeira parte da interface:
![Interface de Teste - Parte 1](https://github.com/CelsoJr85/JWTAuthService/blob/main/screenshots/interface_part1.png)

### Segunda parte da interface:
![Interface de Teste - Parte 2](https://github.com/CelsoJr85/JWTAuthService/blob/main/screenshots/interface_part2.png)

### Como usar a interface:
```bash
# Após clonar o repositório, abra no navegador:
open test_interface.html
# ou
firefox test_interface.html
# ou duplo-clique no arquivo
```

### Funcionalidades disponíveis:
- 🔒 **Hash de Senha** - Gere hashes seguros com bcrypt
- ✅ **Verificar Senha** - Teste correspondência de senhas e hashes
- 🎫 **Criar Tokens** - Gere access e refresh tokens JWT
- 🔍 **Verificar Token** - Valide e decodifique tokens
- 🔄 **Refresh Token** - Renove access tokens automaticamente
- ⚙️ **Configurações** - Ajuste secret key e tempos de expiração

### Fluxo de teste recomendado:
1. **Configure** os parâmetros na seção "Configurações" (opcional)
2. **Gere um hash** de senha na primeira seção
3. **Crie tokens** com dados de usuário fictício
4. **Verifique** os tokens gerados
5. **Teste o refresh** para gerar novo access token

💡 **Dica**: Os dados são automaticamente preenchidos entre as seções para facilitar o teste completo!

## 🤝 Contribuindo

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## ⭐ Suporte

Se este projeto te ajudou, considere dar uma ⭐ no repositório!

Para dúvidas ou problemas, abra uma [issue](https://github.com/CelsoJr85/JWTAuthService/issues).

---

**Feito com ❤️ para a comunidade Python**
