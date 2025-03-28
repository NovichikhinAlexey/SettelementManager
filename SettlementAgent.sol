// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title SettlementAgent
 * @notice Контракт для авторизованного списания ERC20-средств с кошельков клиентов по заданным лимитам и комиссии
 * @dev Использует UUPS-прокси для обновлений, AccessControl для разграничения ролей
 */
contract SettlementAgent is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    string public constant CURRENT_VERSION = "1.7.2";

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant FEEMANAGER_ROLE = keccak256("FEEMANAGER_ROLE");

    IERC20Upgradeable public token;
    address private _settlementAddress;
    address private _feeAddress;

    /// @notice Глобальный процент комиссии (фиксированный, заданный при деплое)
    uint256 public immutable feePercent;

    mapping(address => uint256) public globalLimits;
    mapping(address => uint256) public usedGlobal;
    mapping(address => string) public userApprovedVersion;

    struct TimeLimits {
        uint256 limit10min;
        uint256 limit24h;
    }

    struct Usage {
        uint256 timestamp;
        uint256 amount;
    }

    struct WithdrawalLog {
        uint256 timestamp;
        uint256 amount;
        uint256 fee;
        address executor;
    }

    mapping(address => TimeLimits) public timeLimits;
    mapping(address => Usage[]) private usageHistory;
    mapping(address => WithdrawalLog[]) private withdrawalHistory;
    mapping(address => uint256) public customFeePercent;

    event LimitSet(address indexed user, uint256 amount);
    event TimeLimitsSet(address indexed user, uint256 limit10min, uint256 limit24h);
    event Withdrawal(address indexed user, uint256 amount, uint256 fee);
    event DetailedWithdrawal(address indexed user, uint256 amount, uint256 fee, address indexed executor);
    // event SettlementAddressUpdated удалён: адрес больше не может изменяться после деплоя
    event FeeAddressUpdated(address newAddress);
    event CustomFeeSet(address indexed client, uint256 fee);
    event CustomFeeRemoved(address indexed client);

    constructor(
        address _token,
        address _settlement,
        address _fee,
        uint256 _feePercent,
        address _admin
    ) {
        require(_token != address(0), "Token required");
        require(_settlement != address(0), "Settlement address required");
        require(_fee != address(0), "Fee address required");
        require(_feePercent <= 10000, "Fee too high");
        require(_admin != address(0), "Admin required");

        _disableInitializers();

        token = IERC20Upgradeable(_token);
        _settlementAddress = _settlement;
        _feeAddress = _fee;
        feePercent = _feePercent;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(ADMIN_ROLE, _admin);
        _grantRole(FEEMANAGER_ROLE, _admin);
    }

    /**
     * @notice Устанавливает глобальный лимит на списание для клиента, равный текущему approve.
     * @dev Также сохраняет версию контракта, на которой клиент подтвердил разрешение.
     * Этот вызов необходим перед первым списанием на данной версии контракта.
     */
    function allowLimit() external {
        uint256 allowance = token.allowance(msg.sender, address(this));
        require(allowance > 0, "No allowance set");
        globalLimits[msg.sender] = allowance;
        userApprovedVersion[msg.sender] = CURRENT_VERSION;
        emit LimitSet(msg.sender, allowance);
    }

    /**
     * @notice Устанавливает лимиты на 10 минут и 24 часа для контроля частоты списаний с клиента.
     * @dev Эти лимиты проверяются при каждом списании и защищают от злоупотребления правами менеджера.
     */
    function setTimeLimits(uint256 _limit10min, uint256 _limit24h) external {
        timeLimits[msg.sender] = TimeLimits(_limit10min, _limit24h);
        emit TimeLimitsSet(msg.sender, _limit10min, _limit24h);
    }

    /**
     * @notice Основной метод списания средств с клиента.
     * @dev Проверяет, что клиент подтвердил актуальную версию контракта, лимиты по времени и глобальному объему не превышены,
     * комиссия допустима, а также что хватает allowance и баланса.
     * Выполняет два transferFrom: сумму на settlement адрес и комиссию на fee адрес. Обновляет лимиты и историю списаний.
     * @param client адрес клиента, с которого списываются средства
     * @param amount сумма перевода на settlement адрес
     * @param fee сумма комиссии, которая списывается дополнительно и отправляется на fee адрес
     */
    function withdrawFromClient(address client, uint256 amount, uint256 fee) external onlyRole(MANAGER_ROLE) {
        require(amount > 0, "Amount required");
        uint256 maxAllowedFee = (amount * clientFeePercent(client)) / 10000;
        require(fee <= maxAllowedFee, "Fee exceeds allowed limit");
        require(
            keccak256(bytes(userApprovedVersion[client])) == keccak256(bytes(CURRENT_VERSION)),
            "Client must re-approve"
        );

        uint256 total = amount + fee;
        require(globalLimits[client] >= usedGlobal[client] + total, "Exceeds global limit");

        _cleanUsageHistory(client);

        uint256 used10min = _sumUsage(client, 10 minutes);
        uint256 used24h = _sumUsage(client, 24 hours);

        TimeLimits memory limits = timeLimits[client];
        require(used10min + total <= limits.limit10min, "Exceeds 10min limit");
        require(used24h + total <= limits.limit24h, "Exceeds 24h limit");

        require(token.allowance(client, address(this)) >= total, "Insufficient allowance");
        require(token.balanceOf(client) >= total, "Insufficient balance");

        require(token.transferFrom(client, _settlementAddress, amount), "Transfer to settlement failed");
        if (fee > 0) {
            require(token.transferFrom(client, _feeAddress, fee), "Transfer to fee failed");
        }

        usedGlobal[client] += total;
        usageHistory[client].push(Usage(block.timestamp, total));
        withdrawalHistory[client].push(WithdrawalLog(block.timestamp, amount, fee, msg.sender));

        emit Withdrawal(client, amount, fee);
        emit DetailedWithdrawal(client, amount, fee, msg.sender);
    }

    /**
     * @notice Возвращает агрегированную информацию по лимитам, allowance и комиссиям клиента.
     */
    function getClientFullInfo(address client) external view returns (
        uint256 limit10min,
        uint256 limit24h,
        uint256 usedGlobalAmount,
        uint256 allowance,
        uint256 fee,
        address settlement,
        address feeAddr
    ) {
        TimeLimits memory t = timeLimits[client];
        return (
            t.limit10min,
            t.limit24h,
            usedGlobal[client],
            token.allowance(client, address(this)),
            clientFeePercent(client),
            _settlementAddress,
            _feeAddress
        );
    }

    /**
     * @notice Возвращает актуальный процент комиссии клиента (индивидуальный или глобальный).
     */
    function clientFeePercent(address client) public view returns (uint256) {
        uint256 custom = customFeePercent[client];
        return custom > 0 ? custom : feePercent;
    }

    /**
     * @notice Устанавливает индивидуальный процент комиссии клиенту (не может превышать глобальный).
     */
    function setCustomFeePercent(address client, uint256 percent) external onlyRole(FEEMANAGER_ROLE) {
        require(percent <= feePercent, "Cannot exceed default fee");
        customFeePercent[client] = percent;
        emit CustomFeeSet(client, percent);
    }

    /**
     * @notice Удаляет индивидуальный процент комиссии клиента (будет применяться глобальный).
     */
    function removeCustomFee(address client) external onlyRole(FEEMANAGER_ROLE) {
        delete customFeePercent[client];
        emit CustomFeeRemoved(client);
    }

    /**
     * @notice Обновляет settlement-адрес для переводов (только ADMIN).
     */
    // updateSettlementAddress удалена: теперь смена settlement-адреса возможна только при деплое новой версии контракта

    /**
     * @notice Обновляет fee-адрес для перевода комиссии (только ADMIN).
     */
    function updateFeeAddress(address newAddress) external onlyRole(ADMIN_ROLE) {
        require(newAddress != address(0), "Zero address");
        _feeAddress = newAddress;
        emit FeeAddressUpdated(newAddress);
    }

    /**
     * @notice Возвращает историю списаний клиента.
     */
    function getWithdrawalHistory(address client) external view returns (WithdrawalLog[] memory) {
        return withdrawalHistory[client];
    }

    function _cleanUsageHistory(address client) internal {
        Usage[] storage history = usageHistory[client];
        uint256 cutoff = block.timestamp - 24 hours;
        while (history.length > 0 && history[0].timestamp < cutoff) {
            for (uint256 i = 0; i < history.length - 1; i++) {
                history[i] = history[i + 1];
            }
            history.pop();
        }
    }

    function _sumUsage(address client, uint256 period) internal view returns (uint256 total) {
        Usage[] storage history = usageHistory[client];
        uint256 start = block.timestamp - period;
        for (uint256 i = 0; i < history.length; i++) {
            if (history[i].timestamp >= start) {
                total += history[i].amount;
            }
        }
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {}
}
