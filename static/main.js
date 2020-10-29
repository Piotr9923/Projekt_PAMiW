
document.getElementById("button").disabled = true;
var login_available = false;

function attach_events() {

    var form = document.getElementById("formularz");
    var button = document.getElementById("button");
    var available_login_message = document.getElementById("login_message");
    var login =document.getElementById("login");
    available_login_message.classList.add("unavailable_login_hidden_message");

    login.addEventListener("keydown",function(ev){

        console.log("test");
        if(login_available==false && login.value.length>2){
            console.log("pokaz");
            available_login_message.classList.remove("unavailable_login_hidden_message");
        }else{
            console.log("ukryj");
            available_login_message.classList.add("unavailable_login_hidden_message");
        }


    })

    form.addEventListener("", function (ev) {

        button.disabled = true;

        if (validateFields() == true && login_available == true) button.disabled = false;    

    })

}

function validateFields() {

    var pl_letters = /^[A-Za-zĄĆĘŁŃÓŚŹŻąćęłńóśź]+$/;
    var pl_big_letters = /^[A-ZĄĆĘŁŃÓŚŹŻ]+$/;
    var big_letters = /^[A-Z]+$/;
    var letters = /^[A-Za-z]+$/;
    var password_letters = /^[A-Za-z]+$/;

    is_correct = true;

    var firstname = document.getElementById("firstname");
    if (firstname.value.length > 0) {
        if (firstname.value.match(pl_letters) && firstname.value[0].match(pl_big_letters) && /[a-ząćęłńóśź]/.test(firstname.value)) {
            firstname.classList.remove("incorrect_field");
        }
        else {
            is_correct = false;
            firstname.classList.add("incorrect_field");
        }
    }

    var lastname = document.getElementById("lastname");
    if (lastname.value.length > 0) {
        if (lastname.value.match(pl_letters) && lastname.value[0].match(pl_big_letters) && /[a-ząćęłńóśź]/.test(lastname.value)) {
            lastname.classList.remove("incorrect_field");
        }
        else {
            is_correct = false;
            lastname.classList.add("incorrect_field");
        }
    }

    var login = document.getElementById("login");
    if (login.value.length > 0) {
        if (/[a-z]/.test(login.value) && login.value.length > 2 && login.value.length < 13) {
            login.classList.remove("incorrect_field");
        }
        else {
            is_correct = false;
            login.classList.add("incorrect_field");
        }
    }

    var password = document.getElementById("password");
    if (password.value.length > 0) {
        if (password.value.match(password_letters) && /[A-Z]/.test(password.value) && password.value.length > 7) {
            password.classList.remove("incorrect_field");
        }
        else {
            is_correct = false;
            password.classList.add("incorrect_field");
        }
    }

    var password_again = document.getElementById("password_again");
    if (password_again.value.length > 0) {
        if (password.value == password_again.value) {
            password_again.classList.remove("incorrect_field");
        }
        else {
            is_correct = false;
            password_again.classList.add("incorrect_field");
        }
    }
    var male = document.getElementById("male");
    var female = document.getElementById("female");

    if (!(male.checked || female.checked)) {
        is_correct = false;
    }

    var photo = document.getElementById("photo")

    if (photo.files[0] == undefined) {

        is_correct = false;
    }

    var xhr = new XMLHttpRequest();
    xhr.open("GET", "https://infinite-hamlet-29399.herokuapp.com/check/" + login.value, true);
    xhr.onload = function (e) {

        var DONE = 4;

        if (xhr.readyState == DONE) {
            if (xhr.status >= 200 && xhr.status < 300) {

                json = JSON.parse(xhr.response)
                login_status = json[login.value];

                if (login_status == "taken") {

                    login_available = false;
                }
                else {
                    login_available = true;
                }
            }
        }


    }
    if (login.value.length > 0) {
        xhr.send(null);
    }

    return is_correct
}



attach_events();