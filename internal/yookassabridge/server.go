package yookassabridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type PaymentCreator interface {
	CreatePayment(context.Context, Order, string) (CreatedPayment, error)
	GetPayment(context.Context, string) (YooPayment, error)
}

type RedemptionCreator interface {
	CreateRedemption(context.Context, string, int) (string, error)
}

type Server struct {
	cfg    Config
	store  *Store
	yoo    PaymentCreator
	newAPI RedemptionCreator
}

func NewServer(cfg Config, store *Store, yoo PaymentCreator, newAPI RedemptionCreator) *Server {
	return &Server{cfg: cfg, store: store, yoo: yoo, newAPI: newAPI}
}

func (s *Server) StartReconciler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		s.reconcilePending(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reconcilePending(ctx)
			}
		}
	}()
}

func (s *Server) reconcilePending(ctx context.Context) {
	for _, paymentID := range s.store.PendingPaymentIDs() {
		_, _ = s.syncPayment(ctx, paymentID)
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.handle(mux, "/", s.page)
	s.handle(mux, "/api/plans", s.plans)
	s.handle(mux, "/api/payments", s.createPayment)
	s.handle(mux, "/api/orders/", s.getOrder)
	s.handle(mux, "/success", s.success)
	s.handle(mux, "/webhook/yookassa", s.yooWebhook)
	s.handle(mux, "/submit.php", s.epaySubmit)
	s.handle(mux, "/epay/return", s.epayReturn)
	return mux
}

func (s *Server) handle(mux *http.ServeMux, path string, h http.HandlerFunc) {
	fullPath := s.cfg.BasePath + path
	mux.HandleFunc(fullPath, h)
	if s.cfg.BasePath != "" {
		mux.HandleFunc(path, h)
	}
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != s.cfg.BasePath+"/" && r.URL.Path != s.cfg.BasePath {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplate.Execute(w, map[string]any{"BasePath": s.cfg.BasePath})
}

func (s *Server) success(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.cfg.BasePath+"/?order_id="+r.URL.Query().Get("order_id"), http.StatusFound)
}

func (s *Server) plans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"plans": s.cfg.Plans})
}

func (s *Server) createPayment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		AmountRUB int `json:"amount_rub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	quota, ok := s.quotaForAmount(req.AmountRUB)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown amount"})
		return
	}
	order := Order{
		ID:        newOrderID(),
		AmountRUB: req.AmountRUB,
		Quota:     quota,
		Status:    OrderPending,
	}
	if err := s.store.Create(order); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	created, err := s.yoo.CreatePayment(r.Context(), order, s.cfg.PublicBaseURL+"/success?order_id="+order.ID)
	if err != nil {
		_, _ = s.store.Update(order.ID, func(order Order) Order {
			order.Status = OrderFailed
			order.Error = err.Error()
			return order
		})
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	order, err = s.store.Update(order.ID, func(order Order) Order {
		order.YooPaymentID = created.ID
		order.ConfirmationURL = created.ConfirmationURL
		return order
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, order)
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, s.cfg.BasePath+"/api/orders/")
	id = strings.TrimPrefix(id, "/api/orders/")
	order, ok := s.store.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if order.Status == OrderPending && order.YooPaymentID != "" {
		if synced, err := s.syncPayment(r.Context(), order.YooPaymentID); err == nil {
			order = synced
		}
	}
	writeJSON(w, http.StatusOK, order)
}

func (s *Server) yooWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		Event  string `json:"event"`
		Object struct {
			ID string `json:"id"`
		} `json:"object"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if req.Object.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty payment id"})
		return
	}
	order, err := s.syncPayment(r.Context(), req.Object.ID)
	if err != nil {
		status := http.StatusBadGateway
		if strings.Contains(err.Error(), "order not found") {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, order)
}

func (s *Server) epaySubmit(w http.ResponseWriter, r *http.Request) {
	params, err := requestParams(r)
	if err != nil {
		http.Error(w, "invalid params", http.StatusBadRequest)
		return
	}
	if params["pid"] != s.cfg.EpayPID || !epayVerify(params, s.cfg.EpayKey) {
		http.Error(w, "invalid sign", http.StatusForbidden)
		return
	}
	money := strings.TrimSpace(params["money"])
	if money == "" || params["out_trade_no"] == "" || params["notify_url"] == "" {
		http.Error(w, "missing required params", http.StatusBadRequest)
		return
	}
	amountRUB, err := moneyToIntRUB(money)
	if err != nil {
		http.Error(w, "invalid money", http.StatusBadRequest)
		return
	}
	order := Order{
		ID:            newOrderID(),
		AmountRUB:     amountRUB,
		Status:        OrderPending,
		EpayTradeNo:   params["out_trade_no"],
		EpayType:      params["type"],
		EpayName:      params["name"],
		EpayMoney:     money,
		EpayNotifyURL: params["notify_url"],
		EpayReturnURL: params["return_url"],
	}
	if err := s.store.Create(order); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	returnURL := s.cfg.PublicBaseURL + "/epay/return?out_trade_no=" + url.QueryEscape(order.EpayTradeNo)
	created, err := s.yoo.CreatePayment(r.Context(), order, returnURL)
	if err != nil {
		_, _ = s.store.Update(order.ID, func(order Order) Order {
			order.Status = OrderFailed
			order.Error = err.Error()
			return order
		})
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_, _ = s.store.Update(order.ID, func(order Order) Order {
		order.YooPaymentID = created.ID
		order.ConfirmationURL = created.ConfirmationURL
		return order
	})
	http.Redirect(w, r, created.ConfirmationURL, http.StatusSeeOther)
}

func (s *Server) epayReturn(w http.ResponseWriter, r *http.Request) {
	tradeNo := r.URL.Query().Get("out_trade_no")
	order, ok := s.findByEpayTradeNo(tradeNo)
	if ok && order.YooPaymentID != "" {
		if synced, err := s.syncPayment(r.Context(), order.YooPaymentID); err == nil {
			order = synced
		}
	}
	if ok && order.EpayReturnURL != "" {
		http.Redirect(w, r, order.EpayReturnURL, http.StatusFound)
		return
	}
	http.Redirect(w, r, s.cfg.NewAPIBaseURL+"/console/log", http.StatusFound)
}

func (s *Server) syncPayment(ctx context.Context, paymentID string) (Order, error) {
	payment, err := s.yoo.GetPayment(ctx, paymentID)
	if err != nil {
		return Order{}, err
	}
	orderID := payment.Metadata["order_id"]
	order, ok := s.store.Get(orderID)
	if !ok {
		order, ok = s.store.FindByPaymentID(payment.ID)
	}
	if !ok {
		return Order{}, fmt.Errorf("order not found")
	}
	if payment.Status != "succeeded" || !payment.Paid {
		status := OrderCanceled
		if payment.Status != "canceled" {
			status = OrderPending
		}
		order, _ = s.store.Update(order.ID, func(order Order) Order {
			order.Status = status
			return order
		})
		return order, nil
	}
	if !order.canCredit() {
		return order, nil
	}
	if order.EpayNotifyURL != "" {
		if order.EpayNotified {
			return order, nil
		}
		if err := s.notifyEpaySuccess(ctx, order, payment.ID); err != nil {
			order, _ = s.store.Update(order.ID, func(order Order) Order {
				order.Error = err.Error()
				return order
			})
			return Order{}, err
		}
		order, err = s.store.Update(order.ID, func(order Order) Order {
			order.Status = OrderSucceeded
			order.EpayNotified = true
			order.Error = ""
			return order
		})
		if err != nil {
			return Order{}, err
		}
		return order, nil
	}
	code, err := s.newAPI.CreateRedemption(ctx, fmt.Sprintf("SBP %d RUB", order.AmountRUB), order.Quota)
	if err != nil {
		order, _ = s.store.Update(order.ID, func(order Order) Order {
			order.Error = err.Error()
			return order
		})
		return Order{}, err
	}
	order, err = s.store.Update(order.ID, func(order Order) Order {
		order.Status = OrderSucceeded
		order.RedemptionCode = code
		order.Error = ""
		return order
	})
	if err != nil {
		return Order{}, err
	}
	return order, nil
}

func (s *Server) notifyEpaySuccess(ctx context.Context, order Order, paymentID string) error {
	params := epaySignedParams(map[string]string{
		"pid":          s.cfg.EpayPID,
		"type":         order.EpayType,
		"trade_no":     paymentID,
		"out_trade_no": order.EpayTradeNo,
		"name":         order.EpayName,
		"money":        order.EpayMoney,
		"trade_status": epayTradeSuccess,
	}, s.cfg.EpayKey)
	form := url.Values{}
	for name, value := range params {
		form.Set(name, value)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, order.EpayNotifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("epay notify status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(body)) != "success" {
		return fmt.Errorf("epay notify response %q", strings.TrimSpace(string(body)))
	}
	return nil
}

func (s *Server) findByEpayTradeNo(tradeNo string) (Order, bool) {
	if tradeNo == "" {
		return Order{}, false
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	for _, order := range s.store.Orders {
		if order.EpayTradeNo == tradeNo {
			return order, true
		}
	}
	return Order{}, false
}

func requestParams(r *http.Request) (map[string]string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	params := make(map[string]string, len(r.Form))
	for name := range r.Form {
		params[name] = r.Form.Get(name)
	}
	return params, nil
}

func moneyToIntRUB(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty money")
	}
	before, _, _ := strings.Cut(value, ".")
	amount, err := strconv.Atoi(before)
	if err != nil || amount <= 0 {
		return 0, fmt.Errorf("invalid money")
	}
	return amount, nil
}

func (s *Server) quotaForAmount(amount int) (int, bool) {
	for _, plan := range s.cfg.Plans {
		if plan.AmountRUB == amount {
			return plan.Quota, true
		}
	}
	return 0, false
}

func newOrderID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Пополнение Vibecode API</title>
  <style>
    :root{color-scheme:light dark;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    body{margin:0;background:#f6f7f9;color:#17181c}
    main{max-width:760px;margin:0 auto;padding:40px 18px}
    h1{font-size:28px;margin:0 0 8px}
    p{color:#5b606b;line-height:1.5}
    .panel{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:22px;box-shadow:0 8px 24px rgba(20,24,32,.06)}
    .plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}
    button{height:42px;border:1px solid #cfd5df;border-radius:7px;background:#fff;color:#17181c;font-weight:650;cursor:pointer}
    button.selected,button.primary{background:#1d4ed8;color:#fff;border-color:#1d4ed8}
    button:disabled{opacity:.55;cursor:not-allowed}
    .result{display:none;margin-top:18px;padding:16px;border-radius:8px;background:#eef6ff;border:1px solid #bfdbfe}
    code{font-size:18px;font-weight:700}
    @media (prefers-color-scheme:dark){body{background:#111318;color:#f5f7fb}.panel{background:#191d25;border-color:#2b313d}.plans button{background:#191d25;color:#f5f7fb}.result{background:#162033;border-color:#31405a}p{color:#aab2c0}}
  </style>
</head>
<body>
<main>
  <h1>Пополнение Vibecode API</h1>
  <p>Оплата проходит через ЮKassa по СБП. После успешной оплаты появится одноразовый код пополнения для New API.</p>
  <section class="panel">
    <div id="plans" class="plans"></div>
    <button id="pay" class="primary" disabled>Оплатить по СБП</button>
    <div id="result" class="result"></div>
  </section>
</main>
<script>
const base = "{{.BasePath}}";
let selected = null;
async function loadPlans(){
  const res = await fetch(base + "/api/plans");
  const data = await res.json();
  const box = document.getElementById("plans");
  data.plans.forEach((plan, index) => {
    const btn = document.createElement("button");
    btn.textContent = plan.amount_rub + " ₽";
    btn.onclick = () => {
      selected = plan;
      document.querySelectorAll(".plans button").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      document.getElementById("pay").disabled = false;
    };
    box.appendChild(btn);
    if(index === 0) btn.click();
  });
}
async function createPayment(){
  const btn = document.getElementById("pay");
  btn.disabled = true;
  btn.textContent = "Создаю платеж...";
  try {
    const res = await fetch(base + "/api/payments", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({amount_rub:selected.amount_rub})});
    const order = await res.json();
    if(!res.ok) throw new Error(order.error || "Ошибка создания платежа");
    localStorage.setItem("last_order_id", order.id);
    location.href = order.confirmation_url;
  } catch(e) {
    showResult("Ошибка: " + e.message);
    btn.disabled = false;
    btn.textContent = "Оплатить по СБП";
  }
}
async function pollOrder(id){
  const res = await fetch(base + "/api/orders/" + encodeURIComponent(id));
  if(!res.ok) return;
  const order = await res.json();
  if(order.redemption_code) {
    showResult("Код пополнения: <br><code>" + escapeHtml(order.redemption_code) + "</code>");
    return;
  }
  if(order.status === "failed" && order.error) {
    showResult("Платеж обработан, но код не создан: " + escapeHtml(order.error));
    return;
  }
  showResult("Ожидаю подтверждение оплаты...");
  setTimeout(() => pollOrder(id), 2500);
}
function showResult(html){
  const node = document.getElementById("result");
  node.style.display = "block";
  node.innerHTML = html;
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g, m => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m]));}
document.getElementById("pay").onclick = createPayment;
loadPlans();
const params = new URLSearchParams(location.search);
const orderID = params.get("order_id") || localStorage.getItem("last_order_id");
if(orderID) pollOrder(orderID);
</script>
</body>
</html>`))
