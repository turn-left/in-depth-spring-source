package com.ethen.mongo.repository;

import com.mongodb.client.MongoCollection;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Repository;

import javax.annotation.Resource;

/**
 * mongo文档集合的基本操作
 */
@Repository
public class MongoCollectionRepository {

    @Resource
    private MongoTemplate mongoTemplate;

    /**
     * 创建文档集
     *
     * @param collName
     * @return
     */
    public Object createCollection(String collName) {

        MongoCollection<Document> collection = mongoTemplate.createCollection(collName);

        System.err.println(collection);

        return mongoTemplate.collectionExists(collName) ? "SUCCESS" : "FAIL";
    }

}
