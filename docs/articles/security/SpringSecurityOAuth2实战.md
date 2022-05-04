# Spring Security OAuth2实战

主讲老师：Fox老师

课程内容：

1.OAuth2设计思路详解

2.Spring Security OAuth2使用

3.JWT详解&Spring Security Oauth2整合JWT

4.单点登录分析&Spring Secuirty Oauth2实现SSO



## 1. OAuth2.0介绍

[OAuth](http://en.wikipedia.org/wiki/OAuth)（Open Authorization）是一个关于授权（authorization）的开放网络标准，允许用户授权第三方应用访问他们存储在另外的服务提供者上的信息，而不需要将用户名和密码提供给第三方移动应用或分享他们数据的所有内容。OAuth在全世界得到广泛应用，目前的版本是2.0版。

OAuth协议：https://tools.ietf.org/html/rfc6749  

协议特点：

- 简单：不管是OAuth服务提供者还是应用开发者，都很易于理解与使用；

- 安全：没有涉及到用户密钥等信息，更安全更灵活；

- 开放：任何服务提供商都可以实现OAuth，任何软件开发商都可以使用OAuth；

### 1.1 应用场景

- 原生app授权：app登录请求后台接口，为了安全认证，所有请求都带token信息，如果登录验证、请求后台数据。

- 前后端分离单页面应用：前后端分离框架，前端请求后台数据，需要进行oauth2安全认证，比如使用vue、react后者h5开发的app

- 第三方应用授权登录，比如QQ，微博，微信的授权登录。

有一个"云冲印"的网站，可以将用户储存在Google的照片，冲印出来。用户为了使用该服务，必须让"云冲印"读取自己储存在Google上的照片。只有得到用户的授权，Google才会同意"云冲印"读取这些照片。那么，"云冲印"怎样获得用户的授权呢？

传统方法是，用户将自己的Google用户名和密码，告诉"云冲印"，后者就可以读取用户的照片了。这样的做法有以下几个严重的缺点：

- "云冲印"为了后续的服务，会保存用户的密码，这样很不安全。
- Google不得不部署密码登录，而我们知道，单纯的密码登录并不安全。
- "云冲印"拥有了获取用户储存在Google所有资料的权力，用户没法限制"云冲印"获得授权的范围和有效期。
- 用户只有修改密码，才能收回赋予"云冲印"的权力。但是这样做，会使得其他所有获得用户授权的第三方应用程序全部失效。
- 只要有一个第三方应用程序被破解，就会导致用户密码泄漏，以及所有被密码保护的数据泄漏。

![image-20201130154911256](SpringSecurityOAuth2实战.assets/image-20201130154911256.png)

京东微信登录

![image-20201215200325581](SpringSecurityOAuth2实战.assets/image-20201215200325581.png)

https://www.processon.com/view/link/5fc4a242079129329898f55d

### 1.2 基本概念

（1） **Third-party application**：第三方应用程序，又称"客户端"（client），即上一节例子中的"云冲印"。

（2）**HTTP service**：HTTP服务提供商，简称"服务提供商"，即上一节例子中的Google。

（3）**Resource Owner**：资源所有者，又称"用户"（user）。

（4）**User Agent**：用户代理，比如浏览器。

（5）**Authorization server**：授权服务器，即服务提供商专门用来处理认证授权的服务器。

（6）**Resource server**：资源服务器，即服务提供商存放用户生成的资源的服务器。它与授权服务器，可以是同一台服务器，也可以是不同的服务器。

OAuth的作用就是让"客户端"安全可控地获取"用户"的授权，与"服务商提供商"进行交互。

### 1.3 优缺点

优点：

- 更安全，客户端不接触用户密码，服务器端更易集中保护
- 广泛传播并被持续采用
- 短寿命和封装的token
- 资源服务器和授权服务器解耦
- 集中式授权，简化客户端
- HTTP/JSON友好，易于请求和传递token
- 考虑多种客户端架构场景
- 客户可以具有不同的信任级别  

缺点：

- 协议框架太宽泛，造成各种实现的兼容性和互操作性差
- 不是一个认证协议，本身并不能告诉你任何用户信息。  



## 2. OAuth的设计思路

OAuth在"客户端"与"服务提供商"之间，设置了一个授权层（authorization layer）。"客户端"不能直接登录"服务提供商"，只能登录授权层，以此将用户与客户端区分开来。"客户端"登录授权层所用的令牌（token），与用户的密码不同。用户可以在登录的时候，指定授权层令牌的权限范围和有效期，"客户端"登录授权层以后，"服务提供商"根据令牌的权限范围和有效期，向"客户端"开放用户储存的资料。

OAuth 2.0的运行流程如下图，摘自RFC 6749：

![OAuth运行流程](SpringSecurityOAuth2实战.assets/6a92a862da97a4692c755c7e186dfd07.jpg)

（A）用户打开客户端以后，客户端要求用户给予授权。

（B）用户同意给予客户端授权。

（C）客户端使用上一步获得的授权，向授权服务器申请令牌。

（D）授权服务器对客户端进行认证以后，确认无误，同意发放令牌。

（E）客户端使用令牌，向资源服务器申请获取资源。

（F）资源服务器确认令牌无误，同意向客户端开放资源。

> 令牌（token）与密码（password）的作用是一样的，都可以进入系统，但是有三点差异。
>
> （1）令牌是短期的，到期会自动失效，用户自己无法修改。密码一般长期有效，用户不修改，就不会发生变化。
>
> （2）令牌可以被数据所有者撤销，会立即失效。以上例而言，屋主可以随时取消快递员的令牌。密码一般不允许被他人撤销。
>
> （3）令牌有权限范围（scope），比如只能进小区的二号门。对于网络服务来说，只读令牌就比读写令牌更安全。密码一般是完整权限。
>
> 上面这些设计，保证了令牌既可以让第三方应用获得权限，同时又随时可控，不会危及系统安全。这就是 OAuth 2.0 的优点。

**OAuth 引入了一个授权层，用来分离两种不同的角色：客户端和资源所有者。资源所有者同意以后，资源服务器可以向客户端颁发令牌。客户端通过令牌，去请求数据。**



### 2.1 客户端的授权模式

客户端必须得到用户的授权（authorization grant），才能获得令牌（access token）。OAuth 2.0 对于如何颁发令牌的细节，规定得非常详细。具体来说，一共分成四种授权类型（authorization grant），即四种颁发令牌的方式，适用于不同的互联网场景。1

- 授权码模式（authorization code）
- 密码模式（resource owner password credentials）
- 简化(隐式)模式（implicit）
- 客户端模式（client credentials）

不管哪一种授权方式，第三方应用申请令牌之前，都必须先到系统备案，说明自己的身份，然后会拿到两个身份识别码：客户端 ID（client ID）和客户端密钥（client secret）。这是为了防止令牌被滥用，没有备案过的第三方应用，是不会拿到令牌的。

![image-20201203142134351](SpringSecurityOAuth2实战.assets/image-20201203142134351.png)



#### 授权码模式

**授权码（authorization code）方式，指的是第三方应用先申请一个授权码，然后再用该码获取令牌。**

这种方式是最常用的流程，安全性也最高，它适用于那些有后端的 Web 应用。授权码通过前端传送，令牌则是储存在后端，而且所有与资源服务器的通信都在后端完成。这样的前后端分离，可以避免令牌泄漏。

适用场景：目前市面上主流的第三方验证都是采用这种模式

![授权码模式](SpringSecurityOAuth2实战.assets/8a16a81fbba3d6ba1002921bf6b4feff.jpg)

它的步骤如下：

> （A）用户访问客户端，后者将前者导向授权服务器。
>
> （B）用户选择是否给予客户端授权。
>
> （C）假设用户给予授权，授权服务器将用户导向客户端事先指定的"重定向URI"（redirection URI），同时附上一个授权码。
>
> （D）客户端收到授权码，附上早先的"重定向URI"，向授权服务器申请令牌。这一步是在客户端的后台的服务器上完成的，对用户不可见。
>
> （E）授权服务器核对了授权码和重定向URI，确认无误后，向客户端发送访问令牌（access token）和更新令牌（refresh token）。

1. A网站提供一个链接，用户点击后就会跳转到 B 网站，授权用户数据给 A 网站使用。下面就是 A 网站跳转 B 网站的一个示意链接。

```http
> https://b.com/oauth/authorize?
>   response_type=code&            #要求返回授权码（code）
>   client_id=CLIENT_ID&           #让 B 知道是谁在请求   
>   redirect_uri=CALLBACK_URL&     #B 接受或拒绝请求后的跳转网址 
>   scope=read					   # 要求的授权范围（这里是只读）		
>
```

客户端申请授权的URI，包含以下参数：

- response_type：表示授权类型，必选项，此处的值固定为"code"

- client_id：表示客户端的ID，必选项

- redirect_uri：表示重定向URI，可选项

- scope：表示申请的权限范围，可选项

- state：表示客户端的当前状态，可以指定任意值，授权服务器会原封不动地返回这个值。


2. 用户跳转后，B 网站会要求用户登录，然后询问是否同意给予 A 网站授权。用户表示同意，这时 B 网站就会跳回`redirect_uri`参数指定的网址。跳转时，会传回一个授权码，就像下面这样。

```http
> https://a.com/callback?code=AUTHORIZATION_CODE    #code参数就是授权码
>
```

3. A 网站拿到授权码以后，就可以在后端，向 B 网站请求令牌。 用户不可见，服务端行为

```http
> https://b.com/oauth/token?
>  client_id=CLIENT_ID&
>  client_secret=CLIENT_SECRET&    # client_id和client_secret用来让 B 确认 A 的身份,client_secret参数是保密的，因此只能在后端发请求
>  grant_type=authorization_code&   # 采用的授权方式是授权码
>  code=AUTHORIZATION_CODE&          # 上一步拿到的授权码
>  redirect_uri=CALLBACK_URL		# 令牌颁发后的回调网址	
>
```

4. B 网站收到请求以后，就会颁发令牌。具体做法是向`redirect_uri`指定的网址，发送一段 JSON 数据。

```json
> {    
>   "access_token":"ACCESS_TOKEN",     # 令牌
>   "token_type":"bearer",
>   "expires_in":2592000,
>   "refresh_token":"REFRESH_TOKEN",
>   "scope":"read",
>   "uid":100101,
>   "info":{...}
> }
```

token保存在服务端

#### 简化(隐式)模式

有些 Web 应用是纯前端应用，没有后端。这时就不能用上面的方式了，必须将令牌储存在前端。**RFC 6749 就规定了第二种方式，允许直接向前端颁发令牌，这种方式没有授权码这个中间步骤，所以称为（授权码）"隐藏式"（implicit）**

简化模式不通过第三方应用程序的服务器，直接在浏览器中向授权服务器申请令牌，跳过了"授权码"这个步骤，所有步骤在浏览器中完成，令牌对访问者是可见的，且客户端不需要认证。

这种方式把令牌直接传给前端，是很不安全的。因此，只能用于一些安全要求不高的场景，并且令牌的有效期必须非常短，通常就是会话期间（session）有效，浏览器关掉，令牌就失效了。

![简化模式](SpringSecurityOAuth2实战.assets/202e8e80d8b1740f38bde7a3d889e088.jpg)

它的步骤如下：

> （A）客户端将用户导向授权服务器。
>
> （B）用户决定是否给于客户端授权。
>
> （C）假设用户给予授权，授权服务器将用户导向客户端指定的"重定向URI"，并在URI的Hash部分包含了访问令牌。
>
> （D）浏览器向资源服务器发出请求，其中不包括上一步收到的Hash值。
>
> （E）资源服务器返回一个网页，其中包含的代码可以获取Hash值中的令牌。
>
> （F）浏览器执行上一步获得的脚本，提取出令牌。
>
> （G）浏览器将令牌发给客户端。

1. A 网站提供一个链接，要求用户跳转到 B 网站，授权用户数据给 A 网站使用。

```http
> https://b.com/oauth/authorize?
>   response_type=token&          # response_type参数为token，表示要求直接返回令牌
>   client_id=CLIENT_ID&
>   redirect_uri=CALLBACK_URL&
>   scope=read
>
```

2. 用户跳转到 B 网站，登录后同意给予 A 网站授权。这时，B 网站就会跳回`redirect_uri`参数指定的跳转网址，并且把令牌作为 URL 参数，传给 A 网站。

```http
> https://a.com/callback#token=ACCESS_TOKEN     #token参数就是令牌，A 网站直接在前端拿到令牌。
>
```



#### 密码模式

**如果你高度信任某个应用，RFC 6749 也允许用户把用户名和密码，直接告诉该应用。该应用就使用你的密码，申请令牌，这种方式称为"密码式"（password）。**

在这种模式中，用户必须把自己的密码给客户端，但是客户端不得储存密码。这通常用在用户对客户端高度信任的情况下，比如客户端是操作系统的一部分，或者由一个著名公司出品。而授权服务器只有在其他授权模式无法执行的情况下，才能考虑使用这种模式。

适用场景：自家公司搭建的授权服务器

![密码模式](SpringSecurityOAuth2实战.assets/1e7d96e9ed5ab025afd37c1ca97d1b39.jpg)

它的步骤如下：

> （A）用户向客户端提供用户名和密码。
>
> （B）客户端将用户名和密码发给授权服务器，向后者请求令牌。
>
> （C）授权服务器确认无误后，向客户端提供访问令牌。

1. A 网站要求用户提供 B 网站的用户名和密码，拿到以后，A 就直接向 B 请求令牌。整个过程中，客户端不得保存用户的密码。

```http
> https://oauth.b.com/token?
>   grant_type=password&       # 授权方式是"密码式"
>   username=USERNAME&
>   password=PASSWORD&
>   client_id=CLIENT_ID
>
```

2. B 网站验证身份通过后，直接给出令牌。注意，这时不需要跳转，而是把令牌放在 JSON 数据里面，作为 HTTP 回应，A 因此拿到令牌。

测试

http://localhost:8080/oauth/token?username=fox&password=123456&grant_type=password&scope=select&client_id=client_2&client_secret=123456

![image-20201203145929660](SpringSecurityOAuth2实战.assets/image-20201203145929660.png)



#### 客户端模式

客户端模式（Client Credentials Grant）指客户端以自己的名义，而不是以用户的名义，向"服务提供商"进行授权。

**适用于没有前端的命令行应用，即在命令行下请求令牌。**一般用来提供给我们完全信任的服务器端服务。

![客户端模式](SpringSecurityOAuth2实战.assets/062fff24b9564ca9e0cbf4f702af9ee6.jpg)

它的步骤如下：

> （A）客户端向授权服务器进行身份认证，并要求一个访问令牌。
>
> （B）授权服务器确认无误后，向客户端提供访问令牌。

1. A 应用在命令行向 B 发出请求。

```http
> https://oauth.b.com/token?
>   grant_type=client_credentials&
>   client_id=CLIENT_ID&
>   client_secret=CLIENT_SECRET
```

2. B 网站验证通过以后，直接返回令牌。

测试

http://localhost:8080/oauth/token?grant_type=client_credentials&scope=select&client_id=client_1&client_secret=123456

![image-20201203150217282](SpringSecurityOAuth2实战.assets/image-20201203150217282.png)

### 2.2 令牌的使用

A 网站拿到令牌以后，就可以向 B 网站的 API 请求数据了。

此时，每个发到 API 的请求，都必须带有令牌。具体做法是在请求的头信息，加上一个`Authorization`字段，令牌就放在这个字段里面。

```http
> curl -H "Authorization: Bearer ACCESS_TOKEN" \
> "https://api.b.com"
>
```

测试

![image-20201216150144206](SpringSecurityOAuth2实战.assets/image-20201216150144206.png)

### 2.3 更新令牌

令牌的有效期到了，如果让用户重新走一遍上面的流程，再申请一个新的令牌，很可能体验不好，而且也没有必要。OAuth 2.0 允许用户自动更新令牌。

![image-20201215211216014](SpringSecurityOAuth2实战.assets/image-20201215211216014.png)

具体方法是，B 网站颁发令牌的时候，一次性颁发两个令牌，一个用于获取数据，另一个用于获取新的令牌（refresh token 字段）。令牌到期前，用户使用 refresh token 发一个请求，去更新令牌。

```http
> https://b.com/oauth/token?
>   grant_type=refresh_token&    # grant_type参数为refresh_token表示要求更新令牌
>   client_id=CLIENT_ID&
>   client_secret=CLIENT_SECRET&
>   refresh_token=REFRESH_TOKEN    # 用于更新令牌的令牌
>
```

测试

![image-20201217152549963](SpringSecurityOAuth2实战.assets/image-20201217152549963.png)

## 3. Spring Security OAuth2快速开始

### 3.1 授权服务器

![image-20201215213834183](SpringSecurityOAuth2实战.assets/image-20201215213834183.png)

- Authorize Endpoint ：授权端点，进行授权
- Token Endpoint ：令牌端点，经过授权拿到对应的Token
- Introspection Endpoint ：校验端点，校验Token的合法性
- Revocation Endpoint ：撤销端点，撤销授权  

### 3.2 整体架构  

![image-20201215214235657](SpringSecurityOAuth2实战.assets/image-20201215214235657.png)

流程：

1. 用户访问,此时没有Token。Oauth2RestTemplate会报错，这个报错信息会被Oauth2ClientContextFilter捕获并重定向到认证服务器。
2. 认证服务器通过Authorization Endpoint进行授权，并通过AuthorizationServerTokenServices生成授权码并返回给客户端。
3. 客户端拿到授权码去认证服务器通过Token Endpoint调用AuthorizationServerTokenServices生成Token并返回给客户端
4. 客户端拿到Token去资源服务器访问资源，一般会通过Oauth2AuthenticationManager调用ResourceServerTokenServices进行校验。校验通过可以获取资源。  

### 3.3 授权码模式

引入依赖

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.security.oauth</groupId>
    <artifactId>spring-security-oauth2</artifactId>
    <version>2.3.4.RELEASE</version>
</dependency>
```

或者 引入spring cloud oauth2依赖

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-oauth2</artifactId>
</dependency>

<!-- spring cloud -->
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>Hoxton.SR8</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

配置spring security

```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().permitAll()
                .and().authorizeRequests()
                .antMatchers("/oauth/**").permitAll()
                .anyRequest().authenticated()
                .and().logout().permitAll()
                .and().csrf().disable();
    }
}

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String password = passwordEncoder.encode("123456");
        return new User("fox",password, AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}

@RestController
@RequestMapping("/user")
public class UserController {

    @RequestMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication) {
        return authentication.getPrincipal();
    }
}
```

配置授权服务器

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                //配置client_id
                .withClient("client")
                //配置client-secret
                .secret(passwordEncoder.encode("123123"))
                //配置访问token的有效期
                .accessTokenValiditySeconds(3600)
                //配置刷新token的有效期
                .refreshTokenValiditySeconds(864000)
                //配置redirect_uri，用于授权成功后跳转
                .redirectUris("http://www.baidu.com")
                //配置申请的权限范围
                .scopes("all")
                //配置grant_type，表示授权类型
                .authorizedGrantTypes("authorization_code");
    }
}
```

配置资源服务器

```java
@Configuration
@EnableResourceServer
public class ResourceServiceConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and().requestMatchers().antMatchers("/user/**");

    }
}
```

测试

#### 获取授权码

http://localhost:8080/oauth/authorize?response_type=code&client_id=client
或者
http://localhost:8080/oauth/authorize?response_type=code&client_id=client&redirect_uri=http://www.baidu.com&scope=all

登录之后进入

![image-20201216143931170](SpringSecurityOAuth2实战.assets/image-20201216143931170.png)

选择Approve，点击授权获取授权码

![image-20201216145352741](SpringSecurityOAuth2实战.assets/image-20201216145352741.png)

#### 获取令牌  

根据授权码通过post请求获取

![image-20201216144557107](SpringSecurityOAuth2实战.assets/image-20201216144557107.png)

![image-20201216145247838](SpringSecurityOAuth2实战.assets/image-20201216145247838.png)

grant_type ：授权类型，填写authorization_code，表示授权码模式
code ：授权码，就是刚刚获取的授权码，注意：授权码只使用一次就无效了，需要重新申请。
client_id :客户端标识
redirect_uri ：申请授权码时的跳转url，一定和申请授权码时用的redirect_uri一致。
scope :授权范围。
认证失败服务端返回 401 Unauthorized  

#### 访问资源

根据token去资源服务器获取资源  

![image-20201216150014751](SpringSecurityOAuth2实战.assets/image-20201216150014751.png)

或者

![image-20201218171707978](SpringSecurityOAuth2实战.assets/image-20201218171707978.png)

或者

![image-20201216150144206](SpringSecurityOAuth2实战.assets/image-20201216150144206.png)

### 3.4 简化模式

authorizedGrantType添加implicit

![image-20201218170035593](SpringSecurityOAuth2实战.assets/image-20201218170035593.png)

测试

http://localhost:8080/oauth/authorize?client_id=client&response_type=token&scope=all&redirect_uri=http://www.baidu.com

登录之后进入授权页面，确定授权后浏览器会重定向到指定路径，并以Hash的形式存放在重定向uri的fargment中：  

![image-20201218170304155](SpringSecurityOAuth2实战.assets/image-20201218170304155.png)

### 3.5 密码模式

修改WebSecurityConfig，增加AuthenticationManager

```java
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin().permitAll()
                .and().authorizeRequests()
                .antMatchers("/oauth/**").permitAll()
                .anyRequest().authenticated()
                .and().logout().permitAll()
                .and().csrf().disable();

    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
```

修改AuthorizationServerConfig配置

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig2 extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManagerBean;


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManagerBean) //使用密码模式需要配置
                .allowedTokenEndpointRequestMethods(HttpMethod.GET,HttpMethod.POST); //支持GET,POST请求
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //允许表单认证
        security.allowFormAuthenticationForClients();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        /**
         *授权码模式
         *http://localhost:8080/oauth/authorize?response_type=code&client_id=client&redirect_uri=http://www.baidu.com&scope=all
         *http://localhost:8080/oauth/authorize?response_type=code&client_id=client
         *
         * password模式
         *  http://localhost:8080/oauth/token?username=fox&password=123456&grant_type=password&client_id=client&client_secret=123123&scope=all
         *
         *  客户端模式
         *  http://localhost:8080/oauth/token?grant_type=client_credentials&scope=all&client_id=client&client_secret=123123
         */
        clients.inMemory()
                //配置client_id
                .withClient("client")
                //配置client-secret
                .secret(passwordEncoder.encode("123123"))
                //配置访问token的有效期
                .accessTokenValiditySeconds(3600)
                //配置刷新token的有效期
                .refreshTokenValiditySeconds(864000)
                //配置redirect_uri，用于授权成功后跳转
                .redirectUris("http://www.baidu.com")
                //配置申请的权限范围
                .scopes("all")
                /**
                 * 配置grant_type，表示授权类型
                 * authorization_code: 授权码
                 * password： 密码
                 * client_credentials: 客户端
                 */
                .authorizedGrantTypes("authorization_code","password","client_credentials");
    }
}
```



#### 获取令牌

通过浏览器测试，需要配置支持get请求和表单验证

http://localhost:8080/oauth/token?username=fox&password=123456&grant_type=password&client_id=client&client_secret=123123&scope=all

![image-20201217140407004](SpringSecurityOAuth2实战.assets/image-20201217140407004.png)

通过Postman测试

![image-20201217134835615](SpringSecurityOAuth2实战.assets/image-20201217134835615.png)

![image-20201217134909262](SpringSecurityOAuth2实战.assets/image-20201217134909262.png)



#### 访问资源

![image-20201217134924855](SpringSecurityOAuth2实战.assets/image-20201217134924855.png)



### 3.6 客户端模式

#### 获取令牌

![image-20201217141601406](SpringSecurityOAuth2实战.assets/image-20201217141601406.png)

### 3.7 更新令牌

使用oauth2时，如果令牌失效了，可以使用刷新令牌通过refresh_token的授权模式再次获取access_token。只需修改认证服务器的配置，添加refresh_token的授权模式即可。  

修改授权服务器配置，增加refresh_token配置

```java
@Autowired
private UserService userService;
@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints.authenticationManager(authenticationManagerBean) //使用密码模式需要配置
        // .tokenStore(tokenStore)  //指定token存储到redis
        .reuseRefreshTokens(false)  //refresh_token是否重复使用
        .userDetailsService(userService) //刷新令牌授权包含对用户信息的检查
        .allowedTokenEndpointRequestMethods(HttpMethod.GET,HttpMethod.POST); //支持GET,POST请求
}

 @Override
public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

    /**
         *授权码模式
         *http://localhost:8080/oauth/authorize?response_type=code&client_id=client&redirect_uri=http://www.baidu.com&scope=all
         *http://localhost:8080/oauth/authorize?response_type=code&client_id=client
         *
         * password模式
         *  http://localhost:8080/oauth/token?username=fox&password=123456&grant_type=password&client_id=client&client_secret=123123&scope=all
         *
         *  客户端模式
         *  http://localhost:8080/oauth/token?grant_type=client_credentials&scope=all&client_id=client&client_secret=123123
         */
    clients.inMemory()
        //配置client_id
        .withClient("client")
        //配置client-secret
        .secret(passwordEncoder.encode("123123"))
        //配置访问token的有效期
        .accessTokenValiditySeconds(3600)
        //配置刷新token的有效期
        .refreshTokenValiditySeconds(864000)
        //配置redirect_uri，用于授权成功后跳转
        .redirectUris("http://www.baidu.com")
        //配置申请的权限范围
        .scopes("all")
        /**
                 * 配置grant_type，表示授权类型
                 * authorization_code: 授权码
                 * password： 密码
                 * client_credentials: 客户端
                 * refresh_token: 更新令牌
                 */
        .authorizedGrantTypes("authorization_code","password","client_credentials","refresh_token");
}
```



通过密码模式测试

![image-20201217150502778](SpringSecurityOAuth2实战.assets/image-20201217150502778.png)

http://localhost:8080/oauth/token?grant_type=refresh_token&client_id=client&client_secret=123123&refresh_token=dc03bdc2-ca3b-4690-9265-d31a21896d02

![image-20201217152549963](SpringSecurityOAuth2实战.assets/image-20201217152549963.png)

### 3.8 基于redis存储Token

引入依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-pool2</artifactId>
</dependency>
```

修改application.yaml

```yaml
spring:
  redis:
    host: 127.0.0.1
    database: 0
```

编写redis配置类

```java
@Configuration
public class RedisConfig {
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;
    @Bean
    public TokenStore tokenStore(){
        return new RedisTokenStore(redisConnectionFactory);
    }
}
```

在授权服务器配置中指定令牌的存储策略为Redis  

```java
@Autowired
private TokenStore tokenStore;

@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints.authenticationManager(authenticationManagerBean) //使用密码模式需要配置
        .tokenStore(tokenStore)  //指定token存储到redis
        .reuseRefreshTokens(false)  //refresh_token是否重复使用
        .userDetailsService(userService) //刷新令牌授权包含对用户信息的检查
        .allowedTokenEndpointRequestMethods(HttpMethod.GET,HttpMethod.POST); //支持GET,POST请求
}
```







## 4. 原理分析

#### AuthorizationServerEndpointsConfigurer

![image-20201231162001338](SpringSecurityOAuth2实战.assets/image-20201231162001338.png)

#### TokenEndpoint&AuthorizationEndpoint

OAuth2的接口

![image-20201231192617834](SpringSecurityOAuth2实战.assets/image-20201231192617834.png)

#### FrameworkEndpointHandlerMapping



### 授权服务器

以客户端模式为例

http://localhost:8080/oauth/token?grant_type=client_credentials&scope=select&client_id=client_1&client_secret=123456

```java
ClientCredentialsTokenEndpointFilter  //客户端身份认证核心过滤器
DaoAuthenticationProvider          // 提供身份认证
TokenEndpoint             //Token处理端点
TokenGranter             // Token授与者，用来颁发Token
```



#### @EnableAuthorizationServer

```java
@Configuration
@EnableAuthorizationServer
protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {}

```

```java
public class AuthorizationServerConfigurerAdapter implements AuthorizationServerConfigurer {
    //  配置AuthorizationServer安全认证的相关信息,创建ClientCredentialsTokenEndpointFilter核心过滤器
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception{
	}
	// 配置OAuth2的客户端相关信息
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
	}
	// 配置AuthorizationServerEndpointsConfigurer众多相关类，包括配置身份认证器，配置认证方式，TokenStore，TokenGranter，OAuth2RequestFactory
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
	}

}
```

#### ==ClientCredentialsTokenEndpointFilter==

客户端身份认证核心过滤器

```java
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException, IOException, ServletException {
	...
	String clientId = request.getParameter("client_id");
	String clientSecret = request.getParameter("client_secret");

	...
	clientId = clientId.trim();
	UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(clientId,
			clientSecret);

	return this.getAuthenticationManager().authenticate(authRequest);

}
```

#### ==AuthenticationManager==

![image-20201203151658733](SpringSecurityOAuth2实战.assets/image-20201203151658733.png)

在ClientDetailsUserDetailsService中将client客户端的信息（client_id,client_secret）封装成用户的信息(username,password)

#### ==TokenEndpoint==

 Token处理端点

```java
@FrameworkEndpoint
public class TokenEndpoint extends AbstractEndpoint {

	@RequestMapping(value = "/oauth/token", method=RequestMethod.POST)
	public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam
	Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
		 ...
		String clientId = getClientId(principal);
        // 加载客户端信息
		ClientDetails authenticatedClient = getClientDetailsService().loadClientByClientId(clientId);
		...
         //结合请求信息，创建TokenRequest
		TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(parameters, authenticatedClient);
		...
        //将TokenRequest传递给TokenGranter颁发token
		OAuth2AccessToken token = getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);
		...
		return getResponse(token);

	}

	private TokenGranter tokenGranter;
}
```

#### TokenGranter

![TokenGranter](SpringSecurityOAuth2实战.assets/TokenGranter.png)

TokenGranter的设计思路是使用CompositeTokenGranter管理一个List列表，每一种grantType对应一个具体的真正授权者，CompositeTokenGranter 内部就是在循环调用五种TokenGranter实现类的grant方法，而granter内部则是通过grantType来区分是否是各自的授权类型。

五种类型分别是：

- ResourceOwnerPasswordTokenGranter ==> password密码模式
- AuthorizationCodeTokenGranter ==> authorization_code授权码模式
- ClientCredentialsTokenGranter ==> client_credentials客户端模式
- ImplicitTokenGranter ==> implicit简化模式
- RefreshTokenGranter ==>refresh_token 刷新token专用

#### ==OAuth2AccessToken==

```java
@org.codehaus.jackson.map.annotate.JsonSerialize(using = OAuth2AccessTokenJackson1Serializer.class)
@org.codehaus.jackson.map.annotate.JsonDeserialize(using = OAuth2AccessTokenJackson1Deserializer.class)
@com.fasterxml.jackson.databind.annotation.JsonSerialize(using = OAuth2AccessTokenJackson2Serializer.class)
@com.fasterxml.jackson.databind.annotation.JsonDeserialize(using = OAuth2AccessTokenJackson2Deserializer.class)
public interface OAuth2AccessToken {
	public static String BEARER_TYPE = "Bearer";
	public static String OAUTH2_TYPE = "OAuth2";
	public static String ACCESS_TOKEN = "access_token";
	public static String TOKEN_TYPE = "token_type";
	public static String EXPIRES_IN = "expires_in";
	public static String REFRESH_TOKEN = "refresh_token";
	public static String SCOPE = "scope";
	...
}
```

#### ==AuthorizationServerTokenServices==

```java
public interface AuthorizationServerTokenServices {
	//创建token
	OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException;
	//刷新token
	OAuth2AccessToken refreshAccessToken(String refreshToken, TokenRequest tokenRequest)
			throws AuthenticationException;
	//获取token
	OAuth2AccessToken getAccessToken(OAuth2Authentication authentication);

}
```

创建token时，会调用tokenStore对产生的token和相关信息存储到对应的实现类中，可以是redis，数据库，内存，jwt。

#### TokenStore

![image-20201203155554758](SpringSecurityOAuth2实战.assets/image-20201203155554758.png)



### 资源服务器

#### @EnableResourceServer

```java
public class ResourceServerConfigurerAdapter implements ResourceServerConfigurer {
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated();
	}

}
```

#### ResourceServerSecurityConfigurer

```java
public void configure(HttpSecurity http) throws Exception {
	AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
    //创建OAuth2核心过滤器
	resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
	resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
    //设置OAuth2的身份认证处理器，没有交给spring管理(避免影响非普通的认证流程)
	resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
	if (eventPublisher != null) {
		resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
	}
	if (tokenExtractor != null) {
        //设置TokenExtractor默认的实现BearerTokenExtractor
		resourcesServerFilter.setTokenExtractor(tokenExtractor);
	}
	resourcesServerFilter = postProcess(resourcesServerFilter);
	resourcesServerFilter.setStateless(stateless);

	// @formatter:off
	http
		.authorizeRequests().expressionHandler(expressionHandler)
	.and()
		.addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
		.exceptionHandling()
			.accessDeniedHandler(accessDeniedHandler)//相关的异常处理器，可以重写相关实现，达到自定义异常的目的
			.authenticationEntryPoint(authenticationEntryPoint);
	// @formatter:on
}
```

#### ==OAuth2AuthenticationProcessingFilter==

 OAuth2保护资源的预先认证过滤器

通过携带access_token可以访问受限资源

http://localhost:8080/order/1?access_token=a4e4ccb0-9a51-479a-a86c-376410fd0c00

![image-20201203192221533](SpringSecurityOAuth2实战.assets/image-20201203192221533.png)

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain){
	final HttpServletRequest request = (HttpServletRequest) req;
	final HttpServletResponse response = (HttpServletResponse) res;

	try {
		//从请求中取出身份信息，即access_token，封装到PreAuthenticatedAuthenticationToken  
		Authentication authentication = tokenExtractor.extract(request);

		if (authentication == null) {
			...
		}
		else {
			request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, authentication.getPrincipal());
			if (authentication instanceof AbstractAuthenticationToken) {
				AbstractAuthenticationToken needsDetails = (AbstractAuthenticationToken) authentication;
				needsDetails.setDetails(authenticationDetailsSource.buildDetails(request));
			}
			//认证身份
			Authentication authResult = authenticationManager.authenticate(authentication);
			...
			eventPublisher.publishAuthenticationSuccess(authResult);
			//将身份信息绑定到SecurityContextHolder中
			SecurityContextHolder.getContext().setAuthentication(authResult);
		}
	}
	catch (OAuth2Exception failed) {
		...
		return;
	}

	chain.doFilter(request, response);
}
```

#### TokenExtractor

提取出请求中包含的token

```java
public interface TokenExtractor {

	/**
	 * 在不进行身份验证的情况下从传入请求提取令牌值
	 */
	Authentication extract(HttpServletRequest request);
}
```

- Header中携带

  ```http
  http://localhost:8080/order/1
  Header：
  Authentication：Bearer a4e4ccb0-9a51-479a-a86c-376410fd0c00
  ```

- 作为request请求参数 access_token

  ```http
  http://localhost:8080/order/1?access_token=a4e4ccb0-9a51-479a-a86c-376410fd0c00
  
  http://localhost:8080/order/1
  form param：
  access_token=a4e4ccb0-9a51-479a-a86c-376410fd0c00
  ```

  

#### ==OAuth2AuthenticationManager==

![image-20201203194209686](SpringSecurityOAuth2实战.assets/image-20201203194209686.png)

```java
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	...
	String token = (String) authentication.getPrincipal();
	//借助ResourceServerTokenServices根据token加载客户端身份信息
	OAuth2Authentication auth = tokenServices.loadAuthentication(token);
	...

	checkClientDetails(auth);

	if (authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
		...
	}
	auth.setDetails(authentication.getDetails());
	auth.setAuthenticated(true);
	return auth;

}
```

#### ==ResourceServerTokenServices==

```java
public interface ResourceServerTokenServices {
	//根据accessToken加载客户端信息
	OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException;

	//根据accessToken获取完整的访问令牌详细信息。
	OAuth2AccessToken readAccessToken(String accessToken);

}
```



## 5. JWT

### 5.1 常见的认证机制

#### HTTP Basic Auth

HTTP Basic Auth简单点说明就是每次请求API时都提供用户的username和password，简言之，Basic Auth是配合RESTful API 使用的最简单的认证方式，只需提供用户名密码即可，但由于有把用户名密码暴露给第三方客户端的风险，在生产环境下被使用的越来越少。因此，在开发对外开放的RESTful API时，尽量避免采用HTTP Basic Auth。

#### Cookie Auth

Cookie认证机制就是为一次请求认证在服务端创建一个Session对象，同时在客户端的浏览器端创建了一个Cookie对象；通过客户端带上来Cookie对象来与服务器端的session对象匹配来实现状态管理的。默认的，当我们关闭浏览器的时候，cookie会被删除。但可以通过修改cookie 的expire time使cookie在一定时间内有效。  

![image-20201217212740455](SpringSecurityOAuth2实战.assets/image-20201217212740455.png)



#### OAuth

OAuth（开放授权,Open Authorization）是一个开放的授权标准，允许用户让第三方应用访问该用户在某一web服务上存储的私密的资源（如照片，视频，联系人列表），而无需将用户名和密码提供给第三方应用。如网站通过微信、微博登录等，主要用于第三方登录。OAuth允许用户提供一个令牌，而不是用户名和密码来访问他们存放在特定服务提供者的数据。每一个令牌授权一个特定的第三方系统（例如，视频编辑网站)在特定的时段（例如，接下来的2小时内）内访问特定的资源（例如仅仅是某一相册中的视频）。这样，OAuth让用户可以授权第三方网站访问他们存储在另外服务提供者的某些特定信息，而非所有内容。

下面是OAuth2.0的流程：    

![OAuth运行流程](SpringSecurityOAuth2实战.assets/6a92a862da97a4692c755c7e186dfd07.jpg)

这种基于OAuth的认证机制适用于个人消费者类的互联网产品，如社交类APP等应用，但是不太适合拥有自有认证权限管理的企业应用。
缺点：过重。  

#### Token Auth

使用基于 Token 的身份验证方法，在服务端不需要存储用户的登录记录。大概的流程是这样的：

1. 客户端使用用户名跟密码请求登录
2. 服务端收到请求，去验证用户名与密码
3. 验证成功后，服务端会签发一个 Token，再把这个 Token 发送给客户端
4. 客户端收到 Token 以后可以把它存储起来，比如放在 Cookie 里
5. 客户端每次向服务端请求资源的时候需要带着服务端签发的 Token
6. 服务端收到请求，然后去验证客户端请求里面带着的 Token，如果验证成功，就向客户端返回请求的数据  

![image-20201217214251403](SpringSecurityOAuth2实战.assets/image-20201217214251403.png)

比第一种方式更安全，比第二种方式更节约服务器资源，比第三种方式更加轻量。
Token Auth的优点：

1. 支持跨域访问: Cookie是不允许垮域访问的，这一点对Token机制是不存在的，前提是传输的用户认证信息通过HTTP头传输。
2. 无状态(服务端可扩展性):Token机制在服务端不需要存储session信息，因为Token 自身包含了所有登录用户的信息，只需要在客户端的cookie或本地介质存储状态信息。
3. 更适用CDN: 可以通过内容分发网络请求你服务端的所有资料（如：javascript，HTML,图片等），而你的服务端只要提供API即可。
4. 解耦: 不需要绑定到一个特定的身份验证方案。Token可以在任何地方生成，只要在你的API被调用的时候，你可以进行Token生成调用即可。
5. 更适用于移动应用: 当你的客户端是一个原生平台（iOS, Android，微信小程序等）时，Cookie是不被支持的（你需要通过Cookie容器进行处理），这时采用Token认证机制就会简单得多。
6. CSRF:因为不再依赖于Cookie，所以你就不需要考虑对CSRF（跨站请求伪造）的防范。
7. 性能: 一次网络往返时间（通过数据库查询session信息）比做一次HMACSHA256计算的Token验证和解析要费时得多。
8. 不需要为登录页面做特殊处理: 如果你使用Protractor 做功能测试的时候，不再需要为登录页面做特殊处理。
9. 基于标准化:你的API可以采用标准化的 JSON Web Token (JWT). 这个标准已经存在多个后端库（.NET, Ruby, Java,Python, PHP）和多家公司的支持（如：Firebase,Google, Microsoft）。



### 5.2 JWT

#### 什么是JWT  

JSON Web Token（JWT）是一个开放的行业标准（RFC 7519），它定义了一种简介的、自包含的协议格式，用于在通信双方传递json对象，传递的信息经过数字签名可以被验证和信任。JWT可以使用HMAC算法或使用RSA的公钥/私钥对来签名，防止被篡改。
官网： https://jwt.io/
标准： https://tools.ietf.org/html/rfc7519

JWT令牌的优点：

1. jwt基于json，非常方便解析。
2. 可以在令牌中自定义丰富的内容，易扩展。
3. 通过非对称加密算法及数字签名技术，JWT防止篡改，安全性高。
4. 资源服务使用JWT可不依赖认证服务即可完成授权。

缺点：

​	JWT令牌较长，占存储空间比较大。  

#### JWT组成

一个JWT实际上就是一个字符串，它由三部分组成，头部（header）、载荷（payload）与签名（signature）。

![image-20201218143315750](SpringSecurityOAuth2实战.assets/image-20201218143315750.png)

##### 头部（header）

头部用于描述关于该JWT的最基本的信息：类型（即JWT）以及签名所用的算法（如HMACSHA256或RSA）等。

这也可以被表示成一个JSON对象：

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

然后将头部进行base64加密（该加密是可以对称解密的),构成了第一部分:

```markdown
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
```



##### 载荷（payload）

第二部分是载荷，就是存放有效信息的地方。这个名字像是特指飞机上承载的货品，这些有效信息包含三个部分：

- 标准中注册的声明（建议但不强制使用）  

  **iss**: jwt签发者

  **sub**: jwt所面向的用户

  **aud**: 接收jwt的一方

  **exp**: jwt的过期时间，这个过期时间必须要大于签发时间

  **nbf**: 定义在什么时间之前，该jwt都是不可用的.

  **iat**: jwt的签发时间

  **jti**: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。

- 公共的声明
  公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密.  

- 私有的声明
  私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为base64是对称解密的，意味着该部分信息可以归类为明文信息。  

定义一个payload：

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

然后将其进行base64加密，得到Jwt的第二部分:

```markdown
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
```

##### 签名（signature）

jwt的第三部分是一个签证信息，这个签证信息由三部分组成：

- header (base64后的)
- payload (base64后的)
- secret(盐，一定要保密）  

这个部分需要base64加密后的header和base64加密后的payload使用`.`连接组成的字符串，然后通过header中声明的加密方式进行加盐`secret`组合加密，然后就构成了jwt的第三部分:

```javascript
var encodedString = base64UrlEncode(header) + '.' + base64UrlEncode(payload);

var signature = HMACSHA256(encodedString, 'fox'); // khA7TNYc7_0iELcDyTc7gHBZ_xfIcgbfpzUNWwQtzME
```

将这三部分用`.`连接成一个完整的字符串,构成了最终的jwt:

```markdown
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.khA7TNYc7_0iELcDyTc7gHBZ_xfIcgbfpzUNWwQtzME
```

注意：secret是保存在服务器端的，jwt的签发生成也是在服务器端的，secret就是用来进行jwt的签发和jwt的验证，所以，它就是你服务端的私钥，在任何场景都不应该流露出去。一旦客户端得知这个secret, 那就意味着客户端是可以自我签发jwt了。

#### 如何应用

一般是在请求头里加入`Authorization`，并加上`Bearer`标注：

```javascript
fetch('api/user/1', {
  headers: {
    'Authorization': 'Bearer ' + token
  }
})
```

服务端会验证token，如果验证通过就会返回相应的资源。整个流程就是这样的:

![img](SpringSecurityOAuth2实战.assets/1821058-2e28fe6c997a60c9.png)



### 5.3 JJWT

JJWT是一个提供端到端的JWT创建和验证的Java库，永远免费和开源(Apache License，版本2.0)。JJW很容易使用和理解。它被设计成一个以建筑为中心的流畅界面，隐藏了它的大部分复杂性。  

#### 快速开始

引入依赖

```xml
 <!--JWT依赖-->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

##### 创建token

创建测试类，生成token

```java
@Test
public void test() {
    //创建一个JwtBuilder对象
    JwtBuilder jwtBuilder = Jwts.builder()
        //声明的标识{"jti":"666"}
        .setId("666")
        //主体，用户{"sub":"Fox"}
        .setSubject("Fox")
        //创建日期{"ita":"xxxxxx"}
        .setIssuedAt(new Date())
        //签名手段，参数1：算法，参数2：盐
        .signWith(SignatureAlgorithm.HS256, "123123");
    //获取token
    String token = jwtBuilder.compact();
    System.out.println(token);

    //三部分的base64解密
    System.out.println("=========");
    String[] split = token.split("\\.");
    System.out.println(Base64Codec.BASE64.decodeToString(split[0]));
    System.out.println(Base64Codec.BASE64.decodeToString(split[1]));
    //无法解密
    System.out.println(Base64Codec.BASE64.decodeToString(split[2]));
}
```

运行结果

![image-20201218142352295](SpringSecurityOAuth2实战.assets/image-20201218142352295.png)

##### token的验证解析

在web应用中由服务端创建了token然后发给客户端，客户端在下次向服务端发送请求时需要携带这个token（这就好像是拿着一张门票一样），那服务端接到这个token应该解析出token中的信息（例如用户id）,根据这些信息查询数据库返回相应的结果。  

```java
@Test
public void testParseToken(){
    //token
    String token ="eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI2NjYiLCJzdWIiOiJGb3giLCJpYXQiOjE2MDgyNzI1NDh9" +
        ".Hz7tk6pJaest_jxFrJ4BWiMg3HQxjwY9cGmJ4GQwfuU";
    //解析token获取载荷中的声明对象
    Claims claims = Jwts.parser()
        .setSigningKey("123123")
        .parseClaimsJws(token)
        .getBody();

    System.out.println("id:"+claims.getId());
    System.out.println("subject:"+claims.getSubject());
    System.out.println("issuedAt:"+claims.getIssuedAt());
}
```

![image-20201218151110923](SpringSecurityOAuth2实战.assets/image-20201218151110923.png)

试着将token或签名秘钥篡改一下，会发现运行时就会报错，所以解析token也就是验证token  

![image-20201218151233704](SpringSecurityOAuth2实战.assets/image-20201218151233704.png)

##### token过期校验

有很多时候，我们并不希望签发的token是永久生效的，所以我们可以为token添加一个过期时间。原因：从服务器发出的token，服务器自己并不做记录，就存在一个弊端：服务端无法主动控制某个token的立刻失效。  

![image-20201218151837566](SpringSecurityOAuth2实战.assets/image-20201218151837566.png)

当未过期时可以正常读取，当过期时会引发io.jsonwebtoken.ExpiredJwtException异常。  

![image-20201218152028535](SpringSecurityOAuth2实战.assets/image-20201218152028535.png)

##### 自定义claims

我们刚才的例子只是存储了id和subject两个信息，如果你想存储更多的信息（例如角色）可以自定义claims。

```java
@Test
public void test() {
    //创建一个JwtBuilder对象
    JwtBuilder jwtBuilder = Jwts.builder()
        //声明的标识{"jti":"666"}
        .setId("666")
        //主体，用户{"sub":"Fox"}
        .setSubject("Fox")
        //创建日期{"ita":"xxxxxx"}
        .setIssuedAt(new Date())
        //设置过期时间   1分钟
        .setExpiration(new Date(System.currentTimeMillis()+60*1000))
        //直接传入map
        // .addClaims(map)
        .claim("roles","admin")
        .claim("logo","xxx.jpg")
        //签名手段，参数1：算法，参数2：盐
        .signWith(SignatureAlgorithm.HS256, "123123");
    //获取token
    String token = jwtBuilder.compact();
    System.out.println(token);

    //三部分的base64解密
    System.out.println("=========");
    String[] split = token.split("\\.");
    System.out.println(Base64Codec.BASE64.decodeToString(split[0]));
    System.out.println(Base64Codec.BASE64.decodeToString(split[1]));
    //无法解密
    System.out.println(Base64Codec.BASE64.decodeToString(split[2]));
}

@Test
public void testParseToken(){
    //token
    String token ="eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI2NjYiLCJzdWIiOiJGb3giLCJpYXQiOjE2MDgyNzYzMTUsImV4cCI6MTYwODI3NjM3NSwicm9sZXMiOiJhZG1pbiIsImxvZ28iOiJ4eHguanBnIn0.Geg2tmkmJ9iWCWdvZNE3jRSfRaXaR4P3kiPDG3Lb0z4";
    //解析token获取载荷中的声明对象
    Claims claims = Jwts.parser()
        .setSigningKey("123123")
        .parseClaimsJws(token)
        .getBody();

    System.out.println("id:"+claims.getId());
    System.out.println("subject:"+claims.getSubject());
    System.out.println("issuedAt:"+claims.getIssuedAt());

    DateFormat sf =new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    System.out.println("签发时间:"+sf.format(claims.getIssuedAt()));
    System.out.println("过期时间:"+sf.format(claims.getExpiration()));
    System.out.println("当前时间:"+sf.format(new Date()));

    System.out.println("roles:"+claims.get("roles"));
    System.out.println("logo:"+claims.get("logo"));
}
```

结果

![image-20201218152706232](SpringSecurityOAuth2实战.assets/image-20201218152706232.png)



### 5.4 Spring Security Oauth2整合JWT

#### 整合JWT

在之前的spring security Oauth2的代码基础上修改

引入依赖

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-jwt</artifactId>
    <version>1.0.9.RELEASE</version>
</dependency>
```

添加配置文件JwtTokenStoreConfig.java  

```java
@Configuration
public class JwtTokenStoreConfig {

    @Bean
    public TokenStore jwtTokenStore(){
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(){
        JwtAccessTokenConverter accessTokenConverter = new
                JwtAccessTokenConverter();
        //配置JWT使用的秘钥
        accessTokenConverter.setSigningKey("123123");
        return accessTokenConverter;
    }
}
```

在授权服务器配置中指定令牌的存储策略为JWT  

![image-20201218161615656](SpringSecurityOAuth2实战.assets/image-20201218161615656.png)

用密码模式测试

![image-20201218161857923](SpringSecurityOAuth2实战.assets/image-20201218161857923.png)

发现获取到的令牌已经变成了JWT令牌，将access_token拿到https://jwt.io/ 网站上去解析下可以获得其中内容。  

![image-20201218162108496](SpringSecurityOAuth2实战.assets/image-20201218162108496.png)



#### 扩展JWT中的存储内容

有时候我们需要扩展JWT中存储的内容，这里我们在JWT中扩展一个 key为enhance，value为enhance info 的数据。
继承TokenEnhancer实现一个JWT内容增强器 

```java
public class JwtTokenEnhancer implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken,
                                     OAuth2Authentication authentication) {
        Map<String, Object> info = new HashMap<>();
        info.put("enhance", "enhance info");
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
        return accessToken;
    }
}
```

创建一个JwtTokenEnhancer实例  

```java
@Bean
public JwtTokenEnhancer jwtTokenEnhancer() {
return new JwtTokenEnhancer();
}
```

在授权服务器配置中配置JWT的内容增强器  

```java
@Autowired
private JwtTokenEnhancer jwtTokenEnhancer;

@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    //配置JWT的内容增强器
    TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
    List<TokenEnhancer> delegates = new ArrayList<>();
    delegates.add(jwtTokenEnhancer);
    delegates.add(jwtAccessTokenConverter);
    enhancerChain.setTokenEnhancers(delegates);
    endpoints.authenticationManager(authenticationManagerBean) //使用密码模式需要配置
        .tokenStore(tokenStore)  //配置存储令牌策略
        .accessTokenConverter(jwtAccessTokenConverter)
        .tokenEnhancer(enhancerChain) //配置tokenEnhancer
        .reuseRefreshTokens(false)  //refresh_token是否重复使用
        .userDetailsService(userService) //刷新令牌授权包含对用户信息的检查
        .allowedTokenEndpointRequestMethods(HttpMethod.GET,HttpMethod.POST); //支持GET,POST请求
}
```

运行项目后使用密码模式来获取令牌，之后对令牌进行解析，发现已经包含扩展的内容。  

![image-20201218164043919](SpringSecurityOAuth2实战.assets/image-20201218164043919.png)

#### 解析JWT

添加依赖  

```xml
<!--JWT依赖-->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

修改UserController类，使用jjwt工具类来解析Authorization头中存储的JWT内容  

```java
@GetMapping("/getCurrentUser")
public Object getCurrentUser(Authentication authentication,
                             HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    String token = null;
    if(header!=null){
        token = header.substring(header.indexOf("bearer") + 7);
    }else {
        token = request.getParameter("access_token");
    }
    return Jwts.parser()
        .setSigningKey("123123".getBytes(StandardCharsets.UTF_8))
        .parseClaimsJws(token)
        .getBody();
}
```

将令牌放入Authorization头中，访问如下地址获取信息：
http://localhost:8080/user/getCurrentUser  

![image-20201218164842632](SpringSecurityOAuth2实战.assets/image-20201218164842632.png)



#### 刷新令牌

 http://localhost:8080/oauth/token?grant_type=refresh_token&client_id=client&client_secret=123123&refresh_token=[refresh_token值]

![image-20201218173232497](SpringSecurityOAuth2实战.assets/image-20201218173232497.png)

## 6. Spring Secuirty Oauth2实现SSO

### 6.1 单系统登录机制   single sign on

#### http无状态协议

web应用采用browser/server架构，http作为通信协议。http是无状态协议，浏览器的每一次请求，服务器会独立处理，不与之前或之后的请求产生关联，这个过程用下图说明，三次请求/响应对之间没有任何联系。

![3c91a3bf-25d8-4b1f-8e4a-68535c51aaa8](SpringSecurityOAuth2实战.assets/797930-20161129155231912-1627010726.png)

但这也同时意味着，任何用户都能通过浏览器访问服务器资源，如果想保护服务器的某些资源，必须限制浏览器请求；要限制浏览器请求，必须鉴别浏览器请求，响应合法请求，忽略非法请求；要鉴别浏览器请求，必须清楚浏览器请求状态。既然http协议无状态，那就让服务器和浏览器共同维护一个状态吧！这就是会话机制。

#### 会话机制

浏览器第一次请求服务器，服务器创建一个会话，并将会话的id作为响应的一部分发送给浏览器，浏览器存储会话id，并在后续第二次和第三次请求中带上会话id，服务器取得请求中的会话id就知道是不是同一个用户了，这个过程用下图说明，后续请求与第一次请求产生了关联。

![8a9fb230-d506-4b19-b821-4001c68c4588](SpringSecurityOAuth2实战.assets/797930-20161129155233115-1744636093.png)

服务器在内存中保存会话对象，浏览器怎么保存会话id？

- 请求参数

  将会话id作为每一个请求的参数，服务器接收请求自然能解析参数获得会话id，并借此判断是否来自同一会话，很明显，这种方式不靠谱。

- cookie

　　浏览器自己来维护这个会话id，每次发送http请求时浏览器自动发送会话id，cookie机制正好用来做这件事。cookie是浏览器用来存储少量数据的一种机制，数据以”key/value“形式存储，浏览器发送http请求时自动附带cookie信息。

　　tomcat会话机制当然也实现了cookie，访问tomcat服务器时，浏览器中可以看到一个名为“JSESSIONID”的cookie，这就是tomcat会话机制维护的会话id。

使用了cookie的请求响应过程如下图

![518293d9-64b2-459c-9d45-9f353c757d1f](SpringSecurityOAuth2实战.assets/797930-20161129155234443-99011212.png)

#### 登录状态

有了会话机制，登录状态就好理解了，我们假设浏览器第一次请求服务器需要输入用户名与密码验证身份，服务器拿到用户名密码去数据库比对，正确的话说明当前持有这个会话的用户是合法用户，应该将这个会话标记为“已授权”或者“已登录”等等之类的状态，既然是会话的状态，自然要保存在会话对象中。

tomcat在会话对象中设置登录状态如下

```java
HttpSession session = request.getSession();
session.setAttribute("isLogin", true);
```

用户再次访问时，tomcat在会话对象中查看登录状态

```java
HttpSession session = request.getSession();
session.getAttribute("isLogin");
```

实现了登录状态的浏览器请求服务器模型如下图描述

![70e396fa-1bf2-42f8-a504-ce20306e31fa](SpringSecurityOAuth2实战.assets/797930-20161129155235693-1708276896.png)

每次请求受保护资源时都会检查会话对象中的登录状态，只有 isLogin=true 的会话才能访问，登录机制因此而实现。

### 6.2 多系统的复杂性

web系统早已从久远的单系统发展成为如今由多系统组成的应用群，面对如此众多的系统，用户难道要一个一个登录、然后一个一个注销吗？就像下图描述的这样：

![6dfbb0b1-46c0-4945-a3bf-5f060fa80710](SpringSecurityOAuth2实战.assets/797930-20161129155236615-855014039.png)

web系统由单系统发展成多系统组成的应用群，复杂性应该由系统内部承担，而不是用户。无论web系统内部多么复杂，对用户而言，都是一个统一的整体，也就是说，用户访问web系统的整个应用群与访问单个系统一样，登录/注销只要一次就够了

![9fe14ab3-4254-447b-b850-0436e628c254](SpringSecurityOAuth2实战.assets/797930-20161129155237802-1969340065.png)

单系统登录解决方案的核心是cookie，cookie携带会话id在浏览器与服务器之间维护会话状态。但cookie是有限制的，这个限制就是cookie的域（通常对应网站的域名），浏览器发送http请求时会自动携带与该域匹配的cookie，而不是所有cookie

![4d58ccfa-0114-486d-bec2-c28f2f9eb513](SpringSecurityOAuth2实战.assets/797930-20161129155238881-1171826792.png)

既然这样，为什么不将web应用群中所有子系统的域名统一在一个顶级域名下，例如“*.baidu.com”，然后将它们的cookie域设置为“baidu.com”，这种做法理论上是可以的，甚至早期很多多系统登录就采用这种同域名共享cookie的方式。

然而，可行并不代表好，共享cookie的方式存在众多局限。首先，应用群域名得统一；其次，应用群各系统使用的技术（至少是web服务器）要相同，不然cookie的key值（tomcat为JSESSIONID）不同，无法维持会话，共享cookie的方式是无法实现跨语言技术平台登录的，比如java、php、.net系统之间；第三，cookie本身不安全。

因此，我们需要一种全新的登录方式来实现多系统应用群的登录，这就是单点登录

### 6.3 单点登录

　　什么是单点登录？单点登录全称Single Sign On（以下简称SSO），是指在多系统应用群中登录一个系统，便可在其他所有系统中得到授权而无需再次登录，包括单点登录与单点注销两部分。

#### 登录

　　相比于单系统登录，sso需要一个独立的认证中心，只有认证中心能接受用户的用户名密码等安全信息，其他系统不提供登录入口，只接受认证中心的间接授权。间接授权通过令牌实现，sso认证中心验证用户的用户名密码没问题，创建授权令牌，在接下来的跳转过程中，授权令牌作为参数发送给各个子系统，子系统拿到令牌，即得到了授权，可以借此创建局部会话，局部会话登录方式与单系统的登录方式相同。这个过程，也就是单点登录的原理，用下图说明：

![img](SpringSecurityOAuth2实战.assets/797930-20161203152650974-276822362.png)

下面对上图简要描述

1. 用户访问系统1的受保护资源，系统1发现用户未登录，跳转至sso认证中心，并将自己的地址作为参数
2. sso认证中心发现用户未登录，将用户引导至登录页面
3. 用户输入用户名密码提交登录申请
4. sso认证中心校验用户信息，创建用户与sso认证中心之间的会话，称为全局会话，同时创建授权令牌
5. sso认证中心带着令牌跳转会最初的请求地址（系统1）
6. 系统1拿到令牌，去sso认证中心校验令牌是否有效
7. sso认证中心校验令牌，返回有效，注册系统1
8. 系统1使用该令牌创建与用户的会话，称为局部会话，返回受保护资源
9. 用户访问系统2的受保护资源
10. 系统2发现用户未登录，跳转至sso认证中心，并将自己的地址作为参数
11. sso认证中心发现用户已登录，跳转回系统2的地址，并附上令牌
12. 系统2拿到令牌，去sso认证中心校验令牌是否有效
13. sso认证中心校验令牌，返回有效，注册系统2
14. 系统2使用该令牌创建与用户的局部会话，返回受保护资源

用户登录成功之后，会与sso认证中心及各个子系统建立会话，用户与sso认证中心建立的会话称为全局会话，用户与各个子系统建立的会话称为局部会话，局部会话建立之后，用户访问子系统受保护资源将不再通过sso认证中心，全局会话与局部会话有如下约束关系

1. 局部会话存在，全局会话一定存在
2. 全局会话存在，局部会话不一定存在
3. 全局会话销毁，局部会话必须销毁

#### 注销

单点登录自然也要单点注销，在一个子系统中注销，所有子系统的会话都将被销毁，用下面的图来说明

![img](SpringSecurityOAuth2实战.assets/797930-20161129155242271-222889796.png)

sso认证中心一直监听全局会话的状态，一旦全局会话销毁，监听器将通知所有注册系统执行注销操作

下面对上图简要说明

1. 用户向系统1发起注销请求
2. 系统1根据用户与系统1建立的会话id拿到令牌，向sso认证中心发起注销请求
3. sso认证中心校验令牌有效，销毁全局会话，同时取出所有用此令牌注册的系统地址
4. sso认证中心向所有注册系统发起注销请求
5. 各注册系统接收sso认证中心的注销请求，销毁局部会话
6. sso认证中心引导用户至登录页面

#### 架构

单点登录涉及sso认证中心与众子系统，子系统与sso认证中心需要通信以交换令牌、校验令牌及发起注销请求，因而子系统必须集成sso的客户端，sso认证中心则是sso服务端，整个单点登录过程实质是sso客户端与服务端通信的过程，用下图描述

![fb29685c-487c-42b9-9ceb-6c7ee29e98c9](SpringSecurityOAuth2实战.assets/797930-20161129155244646-2067469767.png)

sso认证中心与sso客户端通信方式有多种，httpClient，web service、rpc、restful api都可以。

### 6.4 Spring Secuirty Oauth2实现

创建客户端：oauth2-sso-client-demo

引入依赖

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-starter-oauth2</artifactId>
    </dependency>

    <!--JWT依赖-->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt</artifactId>
        <version>0.9.1</version>
    </dependency>

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>

</dependencies>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-dependencies</artifactId>
            <version>Hoxton.SR8</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

修改application.properties

```properties
server.port=8081
#防止Cookie冲突，冲突会导致登录验证不通过
server.servlet.session.cookie.name=OAUTH2-CLIENT-SESSIONID01
#授权服务器地址
oauth2-server-url: http://localhost:8080
#与授权服务器对应的配置
security.oauth2.client.client-id=client
security.oauth2.client.client-secret=123123
security.oauth2.client.user-authorization-uri=${oauth2-serverurl}/oauth/authorize
security.oauth2.client.access-token-uri=${oauth2-server-url}/oauth/token
security.oauth2.resource.jwt.key-uri=${oauth2-server-url}/oauth/token_key
```

在启动类上添加@EnableOAuth2Sso注解来启用单点登录功能  

```java 
@SpringBootApplication
@EnableOAuth2Sso  
public class Oauth2SsoClientDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2SsoClientDemoApplication.class, args);
    }

}
```

添加接口用于获取当前登录用户信息  

```java 
@RestController
@RequestMapping("/user")
public class UserController {

    @RequestMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication) {
        return authentication;
    }
}
```

授权服务器：oauth2-jwt-demo

修改授权服务器中的AuthorizationServerConfig类，将绑定的跳转路径为http://localhost:8081/login，并添加获取秘钥时的身份认证

  ![image-20201218205101642](SpringSecurityOAuth2实战.assets/image-20201218205101642.png)

```java
 @Override
public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    //允许表单认证
    security.allowFormAuthenticationForClients()
        // 获取密钥需要身份认证，使用单点登录时必须配置
        .tokenKeyAccess("isAuthenticated()");
}

@Override
public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.inMemory()
        //配置client_id
        .withClient("client")
        //配置client-secret
        .secret(passwordEncoder.encode("123123"))
        //配置访问token的有效期
        .accessTokenValiditySeconds(3600)
        //配置刷新token的有效期
        .refreshTokenValiditySeconds(864000)
        //配置redirect_uri，用于授权成功后跳转
        .redirectUris("http://localhost:8081/login")
        //自动授权配置
		.autoApprove(true)
        //配置申请的权限范围
        .scopes("all")
        /**
                 * 配置grant_type，表示授权类型
                 * authorization_code: 授权码
                 * password： 密码
                 * client_credentials: 客户端
                 * refresh_token: 更新令牌
                 */
        .authorizedGrantTypes("authorization_code","password","refresh_token");
}
```

测试
启动授权服务和客户端服务；
访问客户端需要授权的接口http://localhost:8081/user/getCurrentUser
会跳转到授权服务的登录界面；  

![image-20201218205216686](SpringSecurityOAuth2实战.assets/image-20201218205216686.png)

授权后会跳转到原来需要权限的接口地址，展示登录用户信息  

![image-20201218204857640](SpringSecurityOAuth2实战.assets/image-20201218204857640.png)

模拟两个客户端8081，8082

修改application.yaml配置

```properties
server.port=8082
#防止Cookie冲突，冲突会导致登录验证不通过
server.servlet.session.cookie.name=OAUTH2-CLIENT-SESSIONID${server.port}
```

修改授权服务器配置，配置多个跳转路径

```java
//配置redirect_uri，用于授权成功后跳转
.redirectUris("http://localhost:8081/login",
              "http://localhost:8082/login")
```

8081登录成功之后，8082无需再次登录就可以访问http://localhost:8082/user/getCurrentUser



### 6.5 Spring Cloud中如何实现SSO

![image-20201231170245866](SpringSecurityOAuth2实战.assets/image-20201231170245866.png)网关整合 OAuth2.0 有两种思路，一种是授权服务器生成令牌, 所有请求统一在网关层验证，判断权限等操作；另一种是由各资源服务处理，网关只做请求转发。  比较常用的是第一种，把API网关作为OAuth2.0的资源服务器角色，实现接入客户端权限拦截、令牌解析并转发当前登录用户信息给微服务，这样下游微服务就不需要关心令牌格式解析以及OAuth2.0相关机制了。  

网关在认证授权体系里主要负责两件事：
（1）作为OAuth2.0的资源服务器角色，实现接入方权限拦截。
（2）令牌解析并转发当前登录用户信息（明文token）给微服务
微服务拿到明文token(明文token中包含登录用户的身份和权限信息)后也需要做两件事：
（1）用户授权拦截（看当前用户是否有权访问该资源）
（2）将用户信息存储进当前线程上下文（有利于后续业务逻辑随时获取当前用户信息）  