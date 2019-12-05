import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.fasterxml.jackson.databind.util.JSONPObject;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;

public class GetExample {
    OkHttpClient client = new OkHttpClient();

    String run(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .build();

        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        }
    }

    public static void main(String[] args) throws IOException {
        GetExample example = new GetExample();
        String response = example.run("https://raw.githubusercontent.com/ReCheck-io/hammerJ/master/realObj.json");

        BufferedWriter out = new BufferedWriter(
                new FileWriter("3.pdf"));

        BufferedInputStream bis = null;
        try {
            JSONObject js = new JSONObject(response);
            System.out.println(js.get("payload").toString());
            Files.write(Paths.get("3.pdf"), js.getString("payload").getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }


//    } catch(
//    FileNotFoundException e)
//
//    {
//        e.printStackTrace();
//    } catch(
//    IOException e)
//
//    {
//        e.printStackTrace();
//    }
    }
}


//
//        System.out.println("response: "+
//                  response);
//        String[] data = response.split("\"",8);
//        String category = data[1];
//        System.out.println("category: " + category);
//        //if there are no keywords
//        String keywords = data[3];
//        System.out.println("keywords: "+ keywords);
//        String name = data[5];
//        System.out.println("name: "+ name);
//        int last =  data[7].lastIndexOf("\"");
//        String realPayload = data[7].substring(0,last);
//
//        System.out.println("payload: " +  realPayload);
////        String[] words = StringUtils.split(response);
////        for(int i =0; i<words.length;i++){
////            System.out.print(words[i] + " ");
////
////        }
//    }
//}
