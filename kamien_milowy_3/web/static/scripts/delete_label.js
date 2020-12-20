var buttons = document.getElementsByTagName("button")

function attach_events() {
    for(i=0;i< buttons.length;i++){
        console.log(buttons[i].href)
        buttons[i].addEventListener("click", function(ev){
            
            var link = this.value
            var xhr = new XMLHttpRequest();
            xhr.open("DELETE", link);
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