document.addEventListener("DOMContentLoaded", () => {
    // Replace with the actual URL of your backend API
    const apiUrl = 'https://pholap.online/user/profile';

    fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            document.getElementById('profile-image').src = data.image;
            document.getElementById('profile-name').textContent = data.name;
            document.getElementById('profile-email').textContent = data.email;
            document.getElementById('profile-phone').textContent = data.phone;
            document.getElementById('profile-age').textContent = data.age;
            document.getElementById('profile-gender').textContent = data.gender.gender;

            const interestsList = document.getElementById('profile-interests');
            data.interest.forEach(interest => {
                const li = document.createElement('li');
                li.textContent = interest.interest;
                interestsList.appendChild(li);
            });

            document.getElementById('profile-age-range').textContent = `${data.preference.minage} - ${data.preference.maxage}`;
            document.getElementById('profile-desired-gender').textContent = data.preference.gender === 1 ? "Male" : "Female";
            document.getElementById('profile-desirecity').textContent = data.preference.desirecity;

            document.getElementById('profile-country').textContent = data.address.country;
            document.getElementById('profile-state').textContent = data.address.state;
            document.getElementById('profile-district').textContent = data.address.district;
            document.getElementById('profile-city').textContent = data.address.city;
        })
        .catch(error => {
            console.error('Error fetching profile data:', error);
        });
});
