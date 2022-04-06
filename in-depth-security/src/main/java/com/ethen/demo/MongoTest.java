package com.ethen.demo;


import com.mongodb.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

/**
 * java API 访问 mongo
 *
 * @author ethen
 * @since 2022/04/05
 */
public class MongoTest {

    private static final String MONGO_HOST = "localhost";
    private static final int MONGO_PORT = 27017;
    private static final String MONGO_DB_INSTANCE = "hello-mongo";

    public static void main(String[] args) {
        // 连接到服务
        MongoClient mongoClient = new MongoClient(MONGO_HOST, MONGO_PORT);
        // 连接到数据库
        MongoDatabase mongoDatabase = mongoClient.getDatabase(MONGO_DB_INSTANCE);
        System.err.println("connect to database successfully");
        // 创建collection
        mongoDatabase.createCollection("hiyoyo");
        System.err.println("created collection");
        // 获取collection
        MongoCollection<Document> hiyoyo = mongoDatabase.getCollection("hiyoyo");
        // 插入document
        Document doc = new Document("name", "mongo").append("vendor", "beikunyun").append("type", "database")
                .append("age", 18).append("location", new Document("x", 108.01).append("y", 86.67));
        hiyoyo.insertOne(doc);
        // 统计count
        System.err.println("count:" + hiyoyo.countDocuments());
        // query first
        Document firstDoc = hiyoyo.find().first();
        System.err.println("firstDoc:" + firstDoc.toJson());
        // query loop all
        MongoCursor<Document> iterator = hiyoyo.find().iterator();
        try {
            while (iterator.hasNext()) {
                System.err.println("nextDoc:" + iterator.next().toJson());
            }
        } finally {
            iterator.close();
        }
    }
}
