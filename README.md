## Spring源码深入分析

### roadmap

#### 几个问题

- 分析Spring源码究竟是学什么？Spring真正强大的点是什么？IoC?AOP?
- SpringBoot、mybatis、eureka、ribbon、nacos、sentinel...都是在哪些切入点进行整合的？
- 如何设计适合自己项目的Spring组件？
- Spring框架源码设计思路对项目可扩展性、复用性带来的启示？
  <br>
  Spring真正强大的地方在于可以与众多组件整合、可插拔的能力。学习Spring的精髓，在于在于厘清Spring组件生命周期各个接口的执行时机以及切入点！

#### Spring Framework

- Spring 基础设施&组件
- Spring Bean的生命周期
- Spring IOC
- Spring AOP
- Spring 事务
- Spring 缓存
- Spring MVC原理

#### SpringBoot

- [SpringBoot 自动配置原理](/docs/markdown/articles/Spring自动配置原理.md)
- SpringBoot 内嵌tomcat原理
- SpringBoot starter原理
- SpringBoot 属性注入

#### 基于Spring自定义

### 问题

- 常用BeanPostProcessor总结
    - 常用BeanFactoryPostProcessor总结
- Environment类深入分析
- SpringBoot条件注入总结
- SpringBoot自动装配

### 参考资源

- [叶良辰源码学习笔记](https://yangzhiwen911.github.io/zh/spring/#1-%E4%B8%BA%E4%BB%80%E4%B9%88%E8%A6%81%E5%AD%A6spring-%E6%BA%90%E7%A0%81)
- [方志朋的SpringBoot实战专栏](https://blog.csdn.net/forezp/category_9268735.html?spm=1001.2014.3001.5482)
- [SpringBoot源码深度解析](https://blog.csdn.net/qq_34341457/category_9619395.html?spm=1001.2014.3001.5482)