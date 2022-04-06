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

}
