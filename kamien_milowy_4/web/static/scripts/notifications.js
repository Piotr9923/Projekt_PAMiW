function check_notifications() {
    xhr = new XMLHttpRequest();
    xhr.open("GET","/notifications");
    xhr.onreadystatechange = function(){
        if(xhr.readyState == 4){
            if (xhr.status == 200){
                notifications = JSON.parse(xhr.responseText)["notifications"]

                for(i=0;i<notifications.length;i++){
                    console.log(notifications[i])
                    alert(notifications[i])
                }
                
            }
            else if (xhr.status == 204 || xhr.status == 301 || xhr.status == 0){

            }
            else if (xhr.status == 401){
                clearInterval(interval);
                alert("Brak autoryzacji.");
            }
            else if (xhr.status == 440){
                clearInterval(interval);
                alert("Twoja sesja wygasła.");
            }
            else{
                clearInterval(interval);
                console.log("KOD BŁĘDU: "+ xhr.status)
                alert("Wystąpił błąd łączności z usługą sieciową. Nie można pobrać powiadomień.");
            }
        }
    }
    xhr.send();
}
var interval = setInterval(check_notifications, 1000)