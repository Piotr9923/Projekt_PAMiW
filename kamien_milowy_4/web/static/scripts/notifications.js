function check_notifications() {
    xhr = new XMLHttpRequest();
    xhr.open("GET","/notifications");
    xhr.onreadystatechange = function(){
        if(xhr.readyState == 4){
            console.log(xhr.status)
            if (xhr.status == 200){
                notifications = JSON.parse(xhr.responseText)["notifications"]

                for(i=0;i<notifications.length;i++){
                    alert(notifications[i])
                }
                
            }
            else if (xhr.status == 204){

            }
            else if (xhr.status == 401){
                clearInterval(interval);
                alert("Brak autoryzacji.");
            }
            else{
                clearInterval(interval);
                alert("Wystąpił błąd łączności z usługą sieciową. Nie można pobrać powiadomień.");
            }
        }
    }
    xhr.send();
}
var interval = setInterval(check_notifications, 1000)