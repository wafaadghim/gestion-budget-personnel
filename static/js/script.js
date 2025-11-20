// Script pour la suggestion de catégorie en temps réel
document.addEventListener('DOMContentLoaded', function() {
    const descriptionInput = document.getElementById('description');
    
    if (descriptionInput) {
        descriptionInput.addEventListener('blur', function() {
            const description = this.value;
            
            if (description.length > 3) {
                fetch('/api/suggest_category', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ description: description })
                })
                .then(response => response.json())
                .then(data => {
                    // Vous pourriez utiliser cette information pour pré-remplir
                    // un champ de catégorie ou afficher une suggestion à l'utilisateur
                    console.log('Catégorie suggérée:', data.category);
                })
                .catch(error => {
                    console.error('Erreur:', error);
                });
            }
        });
    }
});