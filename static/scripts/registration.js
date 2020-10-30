firstname_correct = false;
lastname_correct = false;
sex_correct = false;
login_correct = false;
login_available = false;
password_correct = false;
password_again_correct = false;
photo_correct = false;

document.getElementById("login_message").classList.add("unavailable_login_hidden_message");
update_button();

function attach_events() {

    var firstname = document.getElementById("firstname");
    var lastname = document.getElementById("lastname");
    var sex = document.getElementById("sex");
    var male = document.getElementById("male");
    var female = document.getElementById("female");
    var login = document.getElementById("login");
    var password = document.getElementById("password");
    var password_again = document.getElementById("password_again");
    var photo = document.getElementById("photo");

    firstname.addEventListener("keyup", function (ev) {

        if (firstname.value.match(/[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśź]+$/) && firstname.value[0].match(/[A-ZĄĆĘŁŃÓŚŹŻ]+$/) && /[a-ząćęłńóśź]/.test(firstname.value)) {
            firstname.classList.remove("incorrect_field");
            firstname_correct = true;
            
        }
        else {
            is_correct = false;
            firstname.classList.add("incorrect_field");
            firstname_correct = false;
        }
        update_button();

    });

    lastname.addEventListener("keyup", function (ev) {

        if (lastname.value.match(/[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśź]+$/) && lastname.value[0].match(/[A-ZĄĆĘŁŃÓŚŹŻ]+$/) && /[a-ząćęłńóśź]/.test(lastname.value)) {
            lastname.classList.remove("incorrect_field");
            lastname_correct = true;
        }
        else {
            lastname.classList.add("incorrect_field");
            lastname_correct = false;
        }
        update_button();

    });


    sex.addEventListener("click",function(){

        if (male.checked || female.checked) {
            sex_correct = true;
        } else {
            sex_correct = false;
        }
        update_button();

    });
    


    login.addEventListener("keyup", function (ev) {

        if (login.value.toLowerCase()==login.value && login.value.length > 2 && login.value.length < 13) {

            login.classList.remove("incorrect_field");
            login_correct = true;
        }
        else {
            login.classList.add("incorrect_field");
            login_correct = false;
        }
        update_button();

        if (login_correct) {

            var xhr = new XMLHttpRequest();
            xhr.open("GET", "https://infinite-hamlet-29399.herokuapp.com/check/" + login.value, true);
            xhr.onload = function (e) {

                var DONE = 4;

                if (xhr.readyState == DONE) {
                    if (xhr.status == 200) {

                        json = JSON.parse(xhr.response)
                        login_status = json[login.value];

                        if (login_status == "taken") {

                            login_available = false;
                            document.getElementById("login_message").classList.remove("unavailable_login_hidden_message");
                            update_button();
                        }
                        else {
                            login_available = true;
                            document.getElementById("login_message").classList.add("unavailable_login_hidden_message");
                            update_button();
                        }
                    }                  
                }

            }

            xhr.send(null);

        }

    });


    password.addEventListener("keyup", function(ev){

        if (password.value.match(/[A-Za-z]+$/) && /[A-Z]/.test(password.value) && password.value.length > 7) {
            password.classList.remove("incorrect_field");
            password_correct = true;
        }
        else {
            password.classList.add("incorrect_field");
            password_correct = false;
        }
        update_button();
    });

    password_again.addEventListener("keyup", function(ev){

        if (password.value == password_again.value) {
            password_again.classList.remove("incorrect_field");
            password_again_correct = true;
        }
        else {
            password_again.classList.add("incorrect_field");
            password_again_correct = false;
        }
        update_button();
        
    });

    photo.addEventListener("change", function(){

        if (photo.files[0] == undefined) {
            photo_correct = false;
        }
        else{
            photo_correct = true;
        }
        update_button();

    });

}

function update_button(){

    document.getElementById("button").disabled = !(firstname_correct && lastname_correct && sex_correct && login_correct &&
        login_available && password_correct && password_again_correct && photo_correct );

}

attach_events();