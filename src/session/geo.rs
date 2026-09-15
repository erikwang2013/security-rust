// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

use super::store::LoginPoint;

/// 地球平均半径（km），IUGG 均值。
const EARTH_RADIUS_KM: f64 = 6371.0088;

/// 两点大圆距离（km）。坐标均为 (纬度, 经度) 十进制度。
///
/// 用 atan2 形式而非 asin 形式：asin 在两点接近时对浮点误差敏感，
/// atan2 形式在整个定义域上数值稳定。
pub(crate) fn haversine_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    let (lat1, lon1) = (a.0.to_radians(), a.1.to_radians());
    let (lat2, lon2) = (b.0.to_radians(), b.1.to_radians());
    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let h = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    // h 理论上属 [0,1]，浮点误差可能使它略微越界，clamp 防止 sqrt 因轻微的负值出 NaN。
    // 注意这里挡不住 NaN 输入（NaN 与任何值比较恒为 false，clamp 原样返回 NaN）——
    // NaN 由 `sanitize_coords` 在信任边界拦掉，不会走到这里。
    let h = h.clamp(0.0, 1.0);
    2.0 * EARTH_RADIUS_KM * h.sqrt().atan2((1.0 - h).sqrt())
}

/// 坐标合法性校验（信任边界）。非有限值或越界的经纬度一律视为「没有坐标」，
/// 而不是让 NaN 传播下去 —— NaN 参与的比较恒为 false，会静默关掉不可能旅行检测。
pub(crate) fn sanitize_coords(c: Option<(f64, f64)>) -> Option<(f64, f64)> {
    match c {
        Some((lat, lon))
            if lat.is_finite()
                && lon.is_finite()
                && (-90.0..=90.0).contains(&lat)
                && (-180.0..=180.0).contains(&lon) =>
        {
            Some((lat, lon))
        }
        _ => None,
    }
}

/// 区域标识是否变化。大小写不敏感并去除首尾空白，
/// 避免调用方给的 "CN-BJ" / " cn-bj " 被误判为两地。
///
/// 任一侧为 `None` 时返回 `false`（无法判定，不报）—— 调用方可能只在
/// 部分请求上提供位置信息，缺失不应产生误报。
pub(crate) fn location_changed(recorded: Option<&str>, current: Option<&str>) -> bool {
    match (recorded, current) {
        (Some(a), Some(b)) => !a.trim().eq_ignore_ascii_case(b.trim()),
        _ => false,
    }
}

/// 判断这次登录相对上一条记录是否属于「不可能旅行」。
///
/// 返回隐含速度（km/h）当且仅当它超过 `max_kmh`；否则返回 `None`。
/// 缺少任一侧坐标、或时间未前进时返回 `None`（不判定）。
pub(crate) fn impossible_travel(
    prev: &LoginPoint,
    cur: &LoginPoint,
    max_kmh: f64,
) -> Option<f64> {
    let (a, b) = (prev.coords?, cur.coords?);
    // 时间未前进（含相等）：无法计算速度，交给其它检查项
    if cur.at <= prev.at {
        return None;
    }
    let hours = (cur.at - prev.at) as f64 / 3600.0;
    let kmh = haversine_km(a, b) / hours;
    (kmh > max_kmh).then_some(kmh)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEIJING: (f64, f64) = (39.9042, 116.4074);
    const NEW_YORK: (f64, f64) = (40.7128, -74.0060);
    const SHANGHAI: (f64, f64) = (31.2304, 121.4737);

    fn point(coords: Option<(f64, f64)>, at: u64) -> LoginPoint {
        LoginPoint {
            location: None,
            coords,
            at,
        }
    }

    #[test]
    fn haversine_zero_distance() {
        assert!(haversine_km(BEIJING, BEIJING) < 0.001);
    }

    #[test]
    fn haversine_beijing_to_new_york() {
        // 大圆距离约 11000 km，放宽到 ±500 容忍半径取值差异
        let km = haversine_km(BEIJING, NEW_YORK);
        assert!((10_500.0..11_500.0).contains(&km), "got {km}");
    }

    #[test]
    fn haversine_beijing_to_shanghai() {
        // 约 1067 km
        let km = haversine_km(BEIJING, SHANGHAI);
        assert!((1_000.0..1_150.0).contains(&km), "got {km}");
    }

    #[test]
    fn haversine_is_symmetric() {
        let a = haversine_km(BEIJING, NEW_YORK);
        let b = haversine_km(NEW_YORK, BEIJING);
        assert!((a - b).abs() < 1e-9);
    }

    #[test]
    fn haversine_finite_for_extreme_valid_coords() {
        // 有限且在范围内的极端输入恒返回有限非负值。
        // （clamp 只兜浮点误差，不保证 NaN 输入 —— NaN 由 sanitize_coords 在边界拦掉）
        for (a, b) in [
            ((0.0, 0.0), (0.0, 0.0)),
            ((90.0, 0.0), (-90.0, 0.0)),
            ((90.0, 0.0), (90.0, 180.0)),
            ((-90.0, -180.0), (90.0, 180.0)),
            ((-89.9, -180.0), (89.9, 180.0)),
        ] {
            let km = haversine_km(a, b);
            assert!(km.is_finite(), "non-finite for {a:?} -> {b:?}");
            assert!(km >= 0.0, "negative for {a:?} -> {b:?}");
        }
    }

    #[test]
    fn sanitize_coords_rejects_non_finite_and_out_of_range() {
        assert_eq!(sanitize_coords(None), None);
        // NaN / 无穷：clamp 挡不住，必须在这里拦掉
        assert_eq!(sanitize_coords(Some((f64::NAN, 0.0))), None);
        assert_eq!(sanitize_coords(Some((0.0, f64::NAN))), None);
        assert_eq!(sanitize_coords(Some((f64::INFINITY, 0.0))), None);
        assert_eq!(sanitize_coords(Some((f64::NEG_INFINITY, 0.0))), None);
        assert_eq!(sanitize_coords(Some((0.0, f64::INFINITY))), None);
        // 越界
        assert_eq!(sanitize_coords(Some((91.0, 0.0))), None);
        assert_eq!(sanitize_coords(Some((-91.0, 0.0))), None);
        assert_eq!(sanitize_coords(Some((0.0, -181.0))), None);
        assert_eq!(sanitize_coords(Some((0.0, 181.0))), None);
        // 闭区间边界合法
        assert_eq!(sanitize_coords(Some((90.0, 180.0))), Some((90.0, 180.0)));
        assert_eq!(sanitize_coords(Some((-90.0, -180.0))), Some((-90.0, -180.0)));
        assert_eq!(sanitize_coords(Some(BEIJING)), Some(BEIJING));
    }

    #[test]
    fn location_changed_detects_different_region() {
        assert!(location_changed(Some("CN-BJ"), Some("US-NY")));
    }

    #[test]
    fn location_changed_ignores_case_and_whitespace() {
        assert!(!location_changed(Some("CN-BJ"), Some("cn-bj")));
        assert!(!location_changed(Some("cn-bj"), Some("  CN-BJ  ")));
    }

    #[test]
    fn location_changed_false_when_either_side_missing() {
        assert!(!location_changed(None, Some("CN-BJ")));
        assert!(!location_changed(Some("CN-BJ"), None));
        assert!(!location_changed(None, None));
    }

    #[test]
    fn impossible_travel_flags_unrealistic_speed() {
        // 北京→纽约 11000km 在 1 小时内：11000 km/h >> 900
        let prev = point(Some(BEIJING), 1_000);
        let cur = point(Some(NEW_YORK), 1_000 + 3600);
        let kmh = impossible_travel(&prev, &cur, 900.0).expect("should be impossible");
        assert!(kmh > 10_000.0, "got {kmh}");
    }

    #[test]
    fn impossible_travel_allows_realistic_flight() {
        // 北京→纽约 11000km 用 14 小时：约 786 km/h < 900
        let prev = point(Some(BEIJING), 1_000);
        let cur = point(Some(NEW_YORK), 1_000 + 14 * 3600);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
    }

    #[test]
    fn impossible_travel_threshold_boundary() {
        // 同经度上纬差 0.054 度约 6km，30 秒内约 720 km/h，低于 900 不报
        let prev = point(Some((39.9042, 116.4074)), 1_000);
        let cur = point(Some((39.9582, 116.4074)), 1_030);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
        // 同一对点在更低阈值下应触发
        assert!(impossible_travel(&prev, &cur, 500.0).is_some());
    }

    #[test]
    fn impossible_travel_none_without_coords() {
        let prev = point(None, 1_000);
        let cur = point(Some(NEW_YORK), 1_000 + 60);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
        let prev2 = point(Some(BEIJING), 1_000);
        let cur2 = point(None, 1_000 + 60);
        assert!(impossible_travel(&prev2, &cur2, 900.0).is_none());
    }

    #[test]
    fn impossible_travel_none_when_time_not_advanced() {
        let prev = point(Some(BEIJING), 2_000);
        let cur = point(Some(NEW_YORK), 2_000);
        assert!(impossible_travel(&prev, &cur, 900.0).is_none());
        let cur_back = point(Some(NEW_YORK), 1_000);
        assert!(impossible_travel(&prev, &cur_back, 900.0).is_none());
    }

    #[test]
    fn impossible_travel_uses_inferred_speed_above_threshold() {
        // 返回值是隐含速度，不是距离 —— 调用方要用它写日志
        let prev = point(Some(BEIJING), 1_000);
        let cur = point(Some(NEW_YORK), 1_000 + 3600);
        let kmh = impossible_travel(&prev, &cur, 1.0).expect("very low threshold");
        // 11000 km / 1 h ≈ 11000
        assert!(kmh > 10_500.0 && kmh < 11_500.0, "got {kmh}");
    }
}
