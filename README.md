# DetSql

# 介绍

**DetSql**是基于 BurpSuite Java 插件 API 开发的 SQL 注入探测插件，主要作用为快速从 http 流量中筛选出可能存在 SQL 注入的请求，在尽可能减少拦截的情况下提高 SQL 注入测试效率。
<br/>

## 注意

**DetSql**采用 Montoya API 进行开发，BurpSuite 版本需满足（>=2023.12.1）。

# 判断方式

> 为方便叙述使用 value 表示请求的一个参数值，respbody 表示该请求的响应体，value->respbody，表示参数值为 value 时发送请求得到响应体 respbody，以下判断依赖 MySQL，sqlserver，oracle，postgresql 四种数据库某版本测试结果。

<br/>

**_1.报错类型判断_**
<br/>

- 请求中任一参数值+报错 poc 作为新参数值，即 value+poc，其中 poc 包括：',%DF',",%DF",\`,同时增加了 URL 编码的单双引号，在遇到 json 数据时增加了 Unicode 编码的单双引号。
- 生成新请求后发送，响应匹配报错规则，添加了近 100 条正则匹配规则，匹配成功任一规则，即认为存在报错类型注入，标记该参数为 errsql，同时在括号中添加对应的报错正则规则作为备注一起显示，否则认为不存在报错类型注入。
  <br/>

**_2.数字类型判断_**
<br/>

- 当 value 为数字时，且该 value 不为 json 的键值，将发起以下请求判断，否则该 value 将不再判断，
  <br/>
- 原始请求表示为：value->respbody，
  <br/>
- poc1 请求：value-0-0-0->respbody1，请求完成后使用 Levenshtein 方法判断 respbody 和 respbody1 相似度是否超过 90%，如果不满足认为不存在数字类型的注入，否则将发送下一个请求判断，
  <br/>
- poc2 请求：value-abc->respbody2，请求完成后使用 Levenshtein 方法判断 respbody2 和 respbody 相似度是否低于 90%并且 respbody2 和 respbody1 相似度也低于 90%，如果都满足即认为存在数字类型注入，标记该参数为 numsql。
  <br/>

**_3.order 类型注入_**
<br/>

- 当 value 不为空时，发起以下请求判断，否则该 value 将不再判断，
  <br/>
- 原始请求表示为：value->respbody，
  <br/>
- poc1 请求：value,0->respbody1，
  <br/>
- poc2 请求：value,xxxxxx->respbody2，
  <br/>
- 首先使用 Jaccard 方法判断 respbody 和 respbody1 的相似度低于 90%，若满足继续发送 poc2 请求，判断 respbody 和 respbody2 的相似度低于 90%，若满足继续后续判断，若不满足则直接停止判断，
  <br/>
- poc3 请求：value,1->respbody3，
  <br/>
- poc4 请求：value,2->respbody4，
  <br/>
- 先发送 poc3 请求，使用 Jaccard 方法判断 respbody 和 respbody3 的相似度高于 90%，若满足则认为存在 order 类型的注入，若不满足继续发送 poc4 请求判断 respbody 和 respbody4 的相似度是否高于 90%，若满足则认为存在 order 类型的注入，标记该参数为 ordersql，否则认为不存在 order 类型的注入。
  <br/>

**_4.字符类型注入_**
<br/>

- 如果为 json 格式的数据，该键值 value 需被双引号包裹才会发起后续请求判断，否则该 value 将不再判断，
  <br/>
- 原始请求表示为：value->respbody，
  <br/>
- poc1 请求：value'->respbody1，此处为一个单引号，
  <br/>
- poc2 请求：value''->respbody2，此处为两个单引号，
  <br/>
- 首先使用 Levenshtein 方法判断 respbody 和 respbody3 的相似度低于 90%，若满足继续发送 poc2 请求，判断 respbody1 和 respbody2 的相似度低于 90%，注意如果原始请求不存在数据 respbody 和 respbody2 的相似度往往较高，如果原始请求存在数据 respbody 和 respbody2 的相似度往往较低，所有此处判断 respbody1 和 respbody2 的相似度。若满足低于 90%继续后续判断，若不满足则直接停止判断，
  <br/>
- poc3 请求：value'+'->respbody3，此处为两个单引号，
  <br/>
- poc4 请求：value'||'->respbody4，此处为两个单引号，
  <br/>
- 先发送 poc3 请求，使用 Levenshtein 方法判断 respbody 和 respbody3 的相似度高于 90%，若满足则认为存在字符类型的注入，若不满足继续发送 poc4 请求判断 respbody 和 respbody4 的相似度是否高于 90%，若满足则认为存在字符类型的注入，标记该参数为 stringsql，否则认为不存在字符类型的注入。

**_5.附加判断_**
<br/>

- 除了前述通过计算相似度作为判断规则外还添加了响应长度的变化阈值作为判断辅助,从而丰富判断依据，例如两个响应长度相同时可直接判断相似度为百分之百，两个响应长度差超过某个值比如100，就将辅助判断的相似度定位百分之九十，在判断时如果希望此时的相似度较大时为好，则会选择用算法计算出的相似度和辅助判断的相似度两者中较大者去比较；如果两个响应的长度差很小，则会使用算法计算出的相似度去做比较。

# 使用方法

插件装载: Extensions - Installed - Add - Select File - Next

<br/>

## 主面板（dashboard）

<br/>

![](https://files.mdnice.com/user/72769/4a808ce4-338a-4267-a46b-baca61e6f7bf.jpg)

<br/>

> 左上显示原始流量，一共 7 列，从左至右依次为序号，从 0 开始、请求来源，proxy 或 repeater，为减少请求，其他模块来源点的请求将忽略;域名，如https://www.baidu.com;请求方式，get或post、URL路径，该路径不包含参数;响应体长度、漏洞提示，如果漏洞提示栏显示空白表示没有漏洞，否则将显示漏洞类型，如errsql，stringsql，多个存在多个类型使用-拼接显示。右上显示为测试请求流量，一共7列，从左至右依次为参数名、poc、响应体长度、状态码、相似度，使用百分比表示、请求时间、漏洞提示，此处如果测试后不存在漏洞将不显示改请求，只显示测试后存在问题的请求。左下和右下分别显示请求与响应，点击上述的原始请求或测试请求将在此处显示对应的请求和响应。

<br/>

> 报错类型页面

![](https://files.mdnice.com/user/72769/58f2c665-edb2-492e-ac9e-073147b66a73.png)


## 配置面板（config）

![](https://files.mdnice.com/user/72769/4d65d891-2b81-4c00-8327-726d20d1f6ef.jpg)
<br/>

> 白名单为测试的请求域名，如 baidu.com，192.168.1.2，多个域名使用竖线分隔，不能填 C 段，不填表示测试全部；黑名单为禁止测试的域名；禁止后缀为一些静态文件的后缀，默认设置了常见的静态后缀；报错 poc 可自行设置报错类型的测试 poc，当设置了报错 poc 后内置的报错 poc 将不再使用，上述四个配置内容设置后需点击确认后生效。四个复选框，开关点击勾选后启动测试，测试 cookie 勾选后可测试 cookie 参数，只测报错勾选后不再测试除报错类型外其他类型的注入，设置接受 repeater 复选框主要是为了保持代码尽可能简洁，也不再右键中发送功能，接受 repeater 勾选后可监听测试来自 repeater 模块的请求，并且合并了请求去重功能的考虑，只对 proxy 来源请求的去重，请求去重算法为SM3，来自 repeater 模块的请求将不考虑该请求的重复性，是否测试过都将测试。右键中只设置了一个结束该请求测试的功能，如果请求已进入测试列表想要停止测试该请求，可右键点击end this data选项停止该请求，第一种情况为该请求正在等待其他线程的释放此时点击end this data后run状态变为手动停止，第二种情况为该请求已在测试点击end this data后也会停止测试同时run状态栏将不显示任何字符；同时对响应体body的长度做了长度限制，长度超过50000的请求不再测试，长度在10000到50000之间测试速度较慢，此处设置一个较低的线程但基本可满足手动测试的需求。最后添加了可将上述配置保存在文件的功能，可保存或从文件中载入配置。

<br/>


> 手动停止页面

![](https://files.mdnice.com/user/72769/681076cb-157a-4b9b-a429-6ba1692e198f.png)



## 辅助面板（codetool）

![](https://files.mdnice.com/user/72769/35961586-7f38-425e-8d6c-538a4f398fe7.jpg)

<br/>

> 由于 burpsuite 自带的 base64 编码，URL 编码解码遇到中文会出现乱码，因此添加了基于 UTF-8 的可编解码中文的 base64，URL 编码，如果 base64 解码后为 json 字符串可点击 JSON 格式化按钮对其格式化，同时为便于查看中文还增加了 Unicode 解码。
