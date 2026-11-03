package com.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

@RestController
public class PaymentController {

    private final OkHttpClient client = new OkHttpClient();

    @PostMapping("/pay")
    public String charge(@RequestBody String body) throws Exception {
        Request req = new Request.Builder()
                .url("https://api.stripe.com/v1/charges")
                .post(okhttp3.RequestBody.create(body, okhttp3.MediaType.parse("application/json")))
                .build();
        try (Response resp = client.newCall(req).execute()) {
            return resp.body().string();
        }
    }
}
