手机号字段改成加密存储后，一条记录被复制到别的用户行上仍能正常解密：加密不绑定附加数据，记录可整行搬到别的用户；附加数据只拼在密文后面而不参与校验；密钥全局共享，一个租户的密钥可解另一租户的数据；盲索引用明文哈希，彩虹表可反查；盲索引不带密钥，相同值跨租户可关联；重新加密不校验旧密文完整性，先解再解出错误值；版本号不校验，旧版本密文被当成新版本；篡改检测只看长度，同长度改动漏检；策略校验不检查附加数据是否为空；批量处理复用密钥与索引，后一行命中前一行的值。vault/field.py 是核心，tests/unit/test_field.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

仓库布局

sec-field-crypto/
  README.md
  conftest.py
  vault/__init__.py
  vault/field.py
  tests/unit/test_field.py
  tests/behaviour/test_field_edge.py

运行方式

在仓库根执行 pytest tests -q。预期结果恰好 15 failed，且没有 error。

字段表

领域 安全
方向 漏洞检测与攻防
类型 Bugfix
技术栈 Python 3, pytest
依赖 无外部依赖

测试拆分布局

tests/unit/test_field.py 共 10 条契约测试，tests/behaviour/test_field_edge.py 共 5 条边界测试，合计 15 条。该布局按缺陷与边界拆分，不改变题面要求的 15 个红。

测试不可修改

tests 目录不可修改，只允许实现 vault/field.py。实现只使用标准库与 pytest，离线、不使用随机数，密钥材料全部显式传入。
## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

