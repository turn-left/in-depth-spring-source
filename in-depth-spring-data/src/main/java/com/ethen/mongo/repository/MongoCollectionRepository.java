package com.ethen.mongo.repository;

import com.mongodb.client.MongoCollection;
import org.bson.Document;
import org.springframework.data.mongodb.core.CollectionOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.CriteriaDefinition;
import org.springframework.data.mongodb.core.validation.Validator;
import org.springframework.stereotype.Repository;

import javax.annotation.Resource;
import java.util.Set;

/**
 * mongo文档集合的基本操作
 * <p>
 * http://www.mydlq.club/article/85/#documentTop
 */
@Repository
public class MongoCollectionRepository {

    @Resource
    private MongoTemplate mongoTemplate;

    private static final String SUCCESS = "SUCCESS";
    private static final String FAIL = "FAIL";

    /**
     * 创建文档集
     *
     * @param collName
     * @return
     */
    public Object createCollection(String collName) {

        MongoCollection<Document> collection = mongoTemplate.createCollection(collName);

        System.err.println("created:" + collection);

        return mongoTemplate.collectionExists(collName) ? SUCCESS : FAIL;
    }

    /**
     * 创建固定大小文档集合
     *
     * @param collName
     * @param size
     * @param maxCount
     * @return
     */
    public Object createCollection(String collName, long size, long maxCount) {
        CollectionOptions options = CollectionOptions.empty()
                // 创建固定大小的文档集合，固定集合是指有着固定大小的集合，当达到最大值时，它会自动覆盖最早的文档。
                .capped()
                // 固定集合的大小(以千字节KB计算)，当caped=true时须指定该字段
                .size(size)
                // 固定集合中包含的最大文档数量
                .maxDocuments(maxCount);
        MongoCollection<Document> collection = mongoTemplate.createCollection(collName, options);
        System.err.println("created:" + collection);
        return mongoTemplate.collectionExists(collName) ? SUCCESS : FAIL;
    }

    /**
     * 创建【验证文档数据】的集合
     * <p>
     * 创建集合并在文档"插入"与"更新"时进行数据效验，如果符合创建集合设置的条件就进允许更新与插入，否则则按照设置的设置的策略进行处理。
     * <p>
     * 效验级别：
     * - off：关闭数据校验。
     * - strict：(默认值) 对所有的文档"插入"与"更新"操作有效。
     * - moderate：仅对"插入"和满足校验规则的"文档"做"更新"操作有效。对已存在的不符合校验规则的"文档"无效。
     * 执行策略：
     * - error：(默认值) 文档必须满足校验规则，才能被写入。
     * - warn：对于"文档"不符合校验规则的 MongoDB 允许写入，但会记录一条告警到 mongod.log 中去。日志内容记录报错信息以及该"文档"的完整记录。
     *
     * @param collName 集合名称
     * @return result
     */
    public Object createValidateCollection(String collName) {
        // 设置验证条件，只允许岁数大于20的用户的信息写入mongo
        CriteriaDefinition criteria = Criteria.where("age").gt(20);

        CollectionOptions options = CollectionOptions.empty()
                .validator(Validator.criteria(criteria))
                .strictValidation()
                .failOnValidationError();

        mongoTemplate.createCollection(collName, options);

        return mongoTemplate.collectionExists(collName) ? SUCCESS : FAIL;
    }

    /**
     * 查询集合名称列表
     *
     * @return set
     */
    public Set<String> listCollections() {
        return mongoTemplate.getCollectionNames();
    }

    /**
     * 根据名称判断是否存在集合
     *
     * @param collName
     * @return
     */
    public boolean isExist(String collName) {
        return mongoTemplate.collectionExists(collName);
    }

    /**
     * 删除集合
     *
     * @param collName
     */
    public void dropCollection(String collName) {
        mongoTemplate.getCollection(collName).drop();
    }
}
