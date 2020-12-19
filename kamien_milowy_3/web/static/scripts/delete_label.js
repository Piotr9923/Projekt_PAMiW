var buttons = document.getElementsByTagName("button")

function attach_events() {
    for(i=0;i< buttons.length;i++){
        buttons[i].addEventListener("click", function(ev){
            
            var label_id = this.value
            var xhr = new XMLHttpRequest();
            xhr.open("DELETE", "/labels/" + label_id);
            xhr.onload = function (e) {
                var DONE = 4;
                if (xhr.readyState == DONE) {
                    location.reload();

                    if(xhr.status != 200){
                        alert("Wystąpił błąd. Spróbuj ponownie później.")
                    }
                }
            }
            xhr.send();
            
        })

    }
}

attach_events();