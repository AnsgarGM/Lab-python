#include <stdio.h>
#include <curl/curl.h>

// Estructura de datos para almacenar la respuesta recibida
struct Response {
    char* data;
    size_t size;
};

// Callback para escribir los datos recibidos en la estructura de respuesta
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t real_size = size * nmemb;
    struct Response* response = (struct Response*)userp;

    // Reasignar memoria para almacenar los nuevos datos recibidos
    response->data = realloc(response->data, response->size + real_size + 1);
    if (response->data == NULL) {
        printf("Error: Fallo en la asignación de memoria.\n");
        return 0;
    }

    // Copiar los datos recibidos a la estructura de respuesta
    memcpy(&(response->data[response->size]), contents, real_size);
    response->size += real_size;
    response->data[response->size] = '\0';

    return real_size;
}

int main() {
    CURL* curl;
    CURLcode res;

    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Crear una instancia de CURL
    curl = curl_easy_init();
    if (curl) {
        // Estructura de respuesta para almacenar los datos recibidos
        struct Response response = { .data = NULL, .size = 0 };

        // Establecer la URL de la API
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org/?format=json");

        // Establecer el callback para escribir los datos recibidos
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&response);

        // Realizar la solicitud HTTP
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Error en la solicitud HTTP: %s\n", curl_easy_strerror(res));
        } else {
            // Imprimir el resultado de la respuesta
            printf("Respuesta recibida: %s\n", response.data);
        }

        // Liberar la memoria utilizada para almacenar los datos de respuesta
        free(response.data);

        // Liberar la instancia de CURL
        curl_easy_cleanup(curl);
    }

    // Finalizar libcurl
    curl_global_cleanup();

    return 0;
}
