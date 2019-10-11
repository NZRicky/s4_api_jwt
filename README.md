# Symfony4 Application with RESTful API using JWT authentication

## What's inside?

1. Symofny barebones applications for microservices and APIs
2. FosUserBundle
3. LexikJWTAuthenticationBundle for JWT(Json Web Token) authentication

## How to use it?

1. Clone it
2. Composer install package
3. See below configuration



create .env file set

```yaml
PROJECT_NAME=s4
localIp=127.0.0.1
```

build and run

```sh
docker-compose build
docker-compose up -d
```

go into the php-fpm bash

```sh
docker-compose exec php-fpm bash
```

\#cleanup

```sh
mv /application/symfony/* /application
mv /application/symfony/.* /application
rm -Rf /application/symfony
```

try: http://localhost:8000

.env file

!!! use docker inspection to get mysql server ip address

```sh
DATABASE_URL=mysql://sf4_user:sf4_pw@172.22.0.2:3306/sf4_db
```

\# install fos/userbundle

```sh
#inside php-fpm bash
composer require friendsofsymfony/user-bundle
```

\# configuration

```yaml
# FOS user config
fos_user:
    db_driver:      orm # other valid values are 'mongodb', 'couchdb' and 'propel'
    firewall_name:  main
    user_class:     App\Entity\User
    from_email:
        address: "no-reply@demo.com"
        sender_name: "Demo"
    registration:
#        form:
#            type: AppBundle\Form\UserRegisterType
        confirmation:
            enabled: true
            template:   FOSUserBundle:Registration:email.txt.twig
            from_email:
                address:        "no-reply@demo.com"
                sender_name:    "No Reply Registration"
    service:
        mailer: fos_user.mailer.twig_swift
    resetting:
        email:
            template:   FOSUserBundle:Resetting:email.txt.twig
```

\# user entity

```php
namespace App\Entity;
use FOS\UserBundle\Model\User as BaseUser;
use Doctrine\ORM\Mapping as ORM;
/**
 * @ORM\Entity
 * @ORM\Table(name="fos_user")
 */
class User extends BaseUser
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;
    public function __construct()
    {
        parent::__construct();
        // your own logic
    }
}
```

\# firewall

```yaml
#config/packages/security.yaml
security:
    encoders:
        FOS\UserBundle\Model\UserInterface: bcrypt
        Symfony\Component\Security\Core\User\User: plaintext
    role_hierarchy:
        ROLE_ADMIN:         ROLE_USER
        ROLE_SUPER_ADMIN:   ROLE_ADMIN
    providers:
        chain_provider:
            chain:
                providers: [in_memory, fos_userbundle]
        in_memory:
            memory:
                users:
                    superadmin:
                        password: 'superadminpw'
                        roles: ['ROLE_SUPER_ADMIN']
        fos_userbundle:
            id: fos_user.user_provider.username
    access_control:
        - { path: ^/login$, role: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/register, role: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/resetting, role: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/admin/, role: ROLE_ADMIN }
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            pattern: ^/
            form_login:
                provider: chain_provider
                csrf_token_generator: security.csrf.token_manager
                login_path: fos_user_security_login
                check_path: fos_user_security_check
                always_use_default_target_path: false
                default_target_path: admin_admin_index
            logout:
                path:   fos_user_security_logout
                target: fos_user_security_login
            anonymous:    true
```

\# router

```yaml
#config/routes.yaml
api:
    prefix: /api
    resource: '../src/Controller/Api'
```

\# api controller

```php
namespace App\Controller\Api;
use FOS\UserBundle\Model\UserManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Entity\User;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validation;
use Symfony\Component\Validator\Constraints as Assert;
/**
 * @Route("/auth")
 */
class ApiAuthController extends AbstractController
{
    /**
     * @Route("/register", name="api_auth_register",  methods={"POST"})
     * @param Request $request
     * @param UserManagerInterface $userManager
     * @return JsonResponse|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function register(Request $request, UserManagerInterface $userManager)
    {
        $data = json_decode(
            $request->getContent(),
            true
        );
        $validator = Validation::createValidator();
        $constraint = new Assert\Collection(array(
            // the keys correspond to the keys in the input array
            'username' => new Assert\Length(array('min' => 1)),
            'password' => new Assert\Length(array('min' => 1)),
            'email' => new Assert\Email(),
        ));
        $violations = $validator->validate($data, $constraint);
        if ($violations->count() > 0) {
            return new JsonResponse(["error" => (string)$violations], 500);
        }
        $username = $data['username'];
        $password = $data['password'];
        $email = $data['email'];
        $user = new User();
        $user
            ->setUsername($username)
            ->setPlainPassword($password)
            ->setEmail($email)
            ->setEnabled(true)
            ->setRoles(['ROLE_USER'])
            ->setSuperAdmin(false)
        ;
        try {
            $userManager->updateUser($user, true);
        } catch (\Exception $e) {
            return new JsonResponse(["error" => $e->getMessage()], 500);
        }
        //return new JsonResponse(["success" => $user->getUsername(). " has been registered!"], 200);
        
        // receive the token after register
        // Code 307 preserves the request method, while redirectToRoute() is a shortcut metho.
        return $this->redirectToRoute('api_auth_login', [
            'username' => $data['username'],
            'password' => $data['password']
        ], 307);
    }
}
```

\# register a new user

```sh
curl -X POST -H "Content-Type: application/json" http://localhost:8000/api/auth/register -d '{"username":"ricky","password":"abcd", "email":"ricky@admin.com"}'
```


\# get private and public keys

```sh
#inside php-fpm bash
mkdir config/jwt
openssl genrsa -out config/jwt/private.pem -aes256 4096
openssl rsa -pubout -in config/jwt/private.pem -out config/jwt/public.pem
```

\# configuration

```yaml
#config/packages/lexik_jwt_authentication.yaml
lexik_jwt_authentication:
    secret_key: '%env(resolve:JWT_SECRET_KEY)%'
    public_key: '%env(resolve:JWT_PUBLIC_KEY)%'
    pass_phrase: '%env(JWT_PASSPHRASE)%'
    token_ttl: 3600
#.env
JWT_SECRET_KEY=%kernel.project_dir%/config/jwt/private.pem
JWT_PUBLIC_KEY=%kernel.project_dir%/config/jwt/public.pem
JWT_PASSPHRASE=b3a6eade2d457e2c8e95a6ea0f00cdbc #this is the passphrase you set before when genearte private key
```

\# routes

Note: it’s important to put the specific routes before the main ones. See that /api/auth/login is more specific than /api

```sh
#config/routes.yaml
api_auth_login:
    path: /api/auth/login
    methods:  [POST]
api:
    prefix: /api
    resource: '../src/Controller/Api'
```

\# firewals

make sure to put api firewalls before the main. The pattern used for the "main" firewall catches everything, the pattern for "api" catches "/api", so you should put the wildcard AKA main at the end, after the specific cases.

```yaml
#config/packages/security.yaml
security:
	#...
    firewalls:
        dev:
            #...
        api_login:
            pattern:  ^/api/auth/login
            stateless: true
            anonymous: true
            json_login:
                provider: chain_provider
                check_path:               /api/auth/login
                success_handler:          lexik_jwt_authentication.handler.authentication_success
                failure_handler:          lexik_jwt_authentication.handler.authentication_failure
            provider: chain_provider
            
        api_register:
            pattern:  ^/api/auth/register
            stateless: true
            anonymous: true    
            
        api:
            pattern: ^/api
            stateless: true
            anonymous: false
            provider: chain_provider
            guard:
                authenticators:
                    - lexik_jwt_authentication.jwt_token_authenticator
        main:
        	#...
    access_control:
        #...
        - { path: ^/api/auth/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/api/auth/register, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/api, roles: IS_AUTHENTICATED_FULLY }    	
```

\# test

```sh
curl -X POST -H "Content-Type: application/json" http://localhost:8000/api/auth/login -d '{"username":"ricky","password":"abcd"}'
```

\# use barer token to access api


## Happy Coding!







