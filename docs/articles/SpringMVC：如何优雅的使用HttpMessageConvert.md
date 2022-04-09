## 如何优雅地读写HttpServletRequest和HttpServletResponse的请求体          

本文转自： https://www.cnblogs.com/felordcn/p/15753963.html

最近很多交互要同原生的`HttpServletRequest`和`HttpServletResponse`打交道。从`HttpServletRequest`中读取**body**数据封装成某种数据结构；向`HttpServletResponse`写入数据并响应。传统的写法非常不优雅，今天给大家介绍一种比较优雅的方式。

#### HttpMessageConverter

` HttpMessageConverter`是Spring框架提供的一个消息转换器模型，用于在 HTTP 请求和响应之间进行转换的策略接口。它可以对输入消息`HttpInputMessage`进行读；也可以对输出消息`HttpOutputMessage`进行写。

![HttpMessageConverter](/docs/imgs/1739473-20211231173520498-1063856613.png)

**Spring MVC**的消息转换都是通过这个接口的实现来完成的。`HttpMessageConverter`有很多实现：

![HttpMessageConverter常见实现](/docs/imgs/1739473-20211231173520967-672770779.png)

通常**Spring MVC**中处理**Form**表单提交、**JSON**、**XML**、字符串、甚至**Protobuf**都由`HttpMessageConverter `的实现来完成，前端传递到后端的**body**参数，后端返回给前端的数据都是由这个接口完成转换的。在**Spring IoC**中(**Spring MVC**环境)还存在一个存放`HttpMessageConverter`的容器`HttpMessageConverters`:

```
    @Bean
    @ConditionalOnMissingBean
    public HttpMessageConverters messageConverters(ObjectProvider<HttpMessageConverter<?>> converters) {
        return new HttpMessageConverters((Collection)converters.orderedStream().collect(Collectors.toList()));
    }
```

我们可以直接拿来使用。那么到底怎么使用呢？那首先要搞清楚`HttpInputMessage` 和`HttpOutputMessage`是干什么用的。

#### HttpInputMessage

`HttpInputMessage`表示一个 **HTTP** 输入消息，由请求头**headers**和一个可读的请求体**body**组成，通常由服务器端的 **HTTP** 请求句柄或客户端的 **HTTP** 响应句柄实现。

![HttpInputMessage](docs/imgs/1739473-20211231173521291-1633800103.png)

而`HttpServletRequest`是`ServletRequest`的扩展接口，提供了**HTTP Servlet**的请求信息，也包含了请求头和请求体，所以两者是有联系的。我们只要找出两者之间的实际关系就能让`HttpMessageConverter`去读取并处理`HttpServletRequest`携带的请求信息。

#### ServletServerHttpRequest

说实话还真找到了：

![ServletServerHttpRequest](/docs/imgs/1739473-20211231173521513-743547803.png)

`ServletServerHttpRequest`不仅仅是`HttpInputMessage`的实现，它还持有了一个`HttpServletRequest`实例属性，`ServletServerHttpRequest`的所有操作都是基于`HttpServletRequest`进行的。我们可以通过构造为其注入`HttpServletRequest`实例，这样`HttpMessageConverter`就能间接处理`HttpServletRequest`了。

#### 提取请求体实战

这里聚焦的场景是在Servlet过滤器中使用`HttpMessageConverter`，在Spring MVC中不太建议去操作`HttpServletRequest`。我选择了`FormHttpMessageConverter`，它通常用来处理`application/x-www-form-urlencoded`请求。我们编写一个过滤器来拦截请求提取**body**：

```
/**
 * 处理 application/x-www-form-urlencoded 请求
 *
 * @author  felord.cn
 */

@Component
public class FormUrlencodedFilter implements Filter {
    private final FormHttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
    private static final Logger log = LoggerFactory.getLogger(FormUrlencodedFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException {
        String contentType = request.getContentType();
        MediaType type= StringUtils.hasText(contentType)? MediaType.valueOf(contentType):null;
        ServletServerHttpRequest serverHttpRequest = new ServletServerHttpRequest((HttpServletRequest) request);
        
        if (formHttpMessageConverter.canRead(MultiValueMap.class,type)) {
            MultiValueMap<String, String> read = formHttpMessageConverter.read(null, serverHttpRequest);
             log.info("打印读取到的请求体：{}",read);
        }
    }
}
```

然后执行一个`POST`类型，`Content-Type`为`application/x-www-form-urlencoded`的请求：

```
POST /ind HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

a=b123&c=d123&e=f123
```

控制台会打印：

```
2021-12-30 6:43:56.409  INFO 12408 --- [nio-8080-exec-1] sfds: 打印读取到的请求体：{a=[b123], c=[d123], e=[f123]}
```

#### ServletServerHttpResponse

有`ServletServerHttpRequest`就有`ServletServerHttpResponse`，大致原理差不多。它正好和`ServletServerHttpRequest`相反，如果我们需要去处理响应问题，比如想通过`HttpServletResponse`写个JSON响应，大概可以这么写：

```
ServletServerHttpResponse servletServerHttpResponse = new ServletServerHttpResponse(response);
// 使用json converter
MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
//  authentication 指的是需要写的对象实例
mappingJackson2HttpMessageConverter.write(authentication, MediaType.APPLICATION_JSON,servletServerHttpResponse);
```

#### 总结

`HttpMessageConverter`抽象了**HTTP**消息转换的策略，可以帮助我们优雅地处理一些请求响应的问题。不过有一点需要注意，请求体**body**只能读取一次，即使它包裹在`ServletServerHttpRequest`中，要注意和`HttpServletRequestWrapper `的区别。