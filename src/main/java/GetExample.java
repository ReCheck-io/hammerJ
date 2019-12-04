import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;

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
        String response = example.run("https://raw.githubusercontent.com/LearnWebCode/json-example/master/animals-1.json");
//        System.out.println(response);
        String[] words = StringUtils.split(response);
        for(int i =0; i<words.length;i++){
            System.out.print(words[i] + " ");
        }
    }
}
