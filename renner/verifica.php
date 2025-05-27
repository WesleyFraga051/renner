

$cpf = $_POST['cpf'];

$url = 'https://servicos.receita.fazenda.gov.br/Servicos/cpf/Cpf.asmx/ConsultaCPF?CPF=' . $cpf;

$options = array(
    'http' => array(
        'method' => 'GET',
        'header' => 'Content-type: application/xml',
        'ignore_errors' => true
    )
);

$context = stream_context_create($options);
$result = file_get_contents($url, false, $context);

if (strpos($result, '<Situacao_Cadastral>REGULAR</Situacao_Cadastral>') !== false) {
    echo 'CPF válido';
} else {
    echo 'CPF inválido';
}
