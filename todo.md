- 新的代码导入私钥总是失败，WTF...commit:014c12958dcd8907bd827340a39d82e8c5b0ce34, 

>Fix core program start failed  temperarily (#315)

>* Fix core program start failed  temperarily

>* Add Error code for AddNewKey



## 多签签名序列化似乎有1个bug

如果成员过多，那么hex就比较长，供n个成员的话 hexBytesLen = 2 + 33n

如此，签名的长度为 hexBytesLen + 约65+ 
实际的多签成员数量不能超过6